using System.Linq.Expressions;
using Honeypot.Api.Data;
using Honeypot.Api.Data.Models;
using Honeypot.Shared.Models;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace Honeypot.Api.Service.impl;

/// <summary>页面与邮件共用的历史报告查询；计数、去重和分组在 SQLite 中执行。</summary>
public sealed class SqliteReportService(
    IDbContextFactory<HoneypotDbContext> factory,
    TimeProvider time,
    IIPLocationResolver? locationResolver = null) : IReportService
{
    private const long HourMs = 3_600_000;
    private const long DayMs = 24 * HourMs;

    public async Task<OperationReport> GenerateAsync(ReportQuery query, CancellationToken cancellationToken = default)
    {
        var now = time.GetUtcNow();
        var (period, previousStart, previousEnd) = ResolvePeriod(query, now);
        var start = period.StartAtUtc.ToUnixTimeMilliseconds();
        var end = period.EndAtUtc.ToUnixTimeMilliseconds();
        await using var db = await factory.CreateDbContextAsync(cancellationToken);
        await db.Database.OpenConnectionAsync(cancellationToken);
        // 只读延迟事务让本次所有聚合看到同一个数据库快照，避免接收新事件时卡片与排行不一致。
        await using var transaction = ((SqliteConnection)db.Database.GetDbConnection()).BeginTransaction(deferred: true);
        await db.Database.UseTransactionAsync(transaction, cancellationToken);
        var facts = Facts(db, start, end);
        var coverage = await CoverageAsync(db, start, end, cancellationToken);
        var totals = await TotalsAsync(db, start, end, cancellationToken);
        var oldStart = previousStart.ToUnixTimeMilliseconds();
        var oldEnd = previousEnd.ToUnixTimeMilliseconds();
        var oldCoverage = await CoverageAsync(db, oldStart, oldEnd, cancellationToken);
        var oldTotals = await TotalsAsync(db, oldStart, oldEnd, cancellationToken);
        // 同进度比较还必须保证区间等长，短月被截断时不能把时间长度差解释为活动变化。
        var equalDuration = end - start == oldEnd - oldStart;
        var comparable = equalDuration && coverage.Status == "complete" && oldCoverage.Status == "complete";
        var comparison = new ReportComparison(previousStart, previousEnd, oldCoverage.Status, oldTotals,
            comparable ? Change(totals.AcceptedConnections, oldTotals.AcceptedConnections) : null,
            comparable ? Change(totals.UniqueSourceIps, oldTotals.UniqueSourceIps) : null,
            comparable ? Change(totals.AuthenticationFailures, oldTotals.AuthenticationFailures) : null);
        var protocols = await BreakdownAsync(facts, item => item.AdapterKey == "" ? "unknown" : item.AdapterKey, 10, cancellationToken);
        var ports = await BreakdownAsync(facts, item => item.DestinationPort.ToString(), 10, cancellationToken);
        var sourceRows = await BreakdownAsync(facts.Where(item => item.SourceIp != ""), item => item.SourceIp, 1000, cancellationToken);
        var invalidSources = await BreakdownAsync(facts.Where(item => item.SourceIp == ""), _ => "未知来源地址", 1, cancellationToken);
        var usernames = await BreakdownAsync(facts.Where(item => item.EventType == "authenticationattempted"),
            item => item.Username == "" ? "unknown" : item.Username, 10, cancellationToken);
        var methods = await BreakdownAsync(facts.Where(item => item.EventType == "authenticationattempted"),
            item => item.AuthenticationMethod == "" ? "unknown" : item.AuthenticationMethod, 10, cancellationToken);
        var risks = await BreakdownAsync(facts, item => item.RiskSignal, 10, cancellationToken);
        var evidence = await BreakdownAsync(facts.Where(item => item.CredentialArtifactId != null), item => item.EvidenceKind, 10, cancellationToken);
        var trend = await TrendAsync(db, facts, start, end, period.Granularity == "hour" ? HourMs : DayMs, cancellationToken);
        var runtime = await RuntimeAsync(db, start, end, cancellationToken);
        var notes = new List<string>
        {
            "连接仅统计 TCP 已接受连接；同一连接的握手、认证和关闭事件不会重复计为连接。",
            "新来源指报告采集启用后首次记录的 IP，不代表互联网中的首次活动。",
            "风险分组只表示事件自身 RiskDelta 增量，不代表历史威胁档案评分或实际封禁。",
            "趋势中的数值为已记录事件数；未覆盖的时段不能据此认定没有活动。",
            "CPU 为蜜罐进程占全部逻辑处理器算力百分比；内存为进程工作集；监听状态为采样正常比例。",
            "地区按报告生成时的 IP 解析缓存分组，不是事件发生时的历史归属地；未知、未启用或待解析会单列。"
        };
        if (coverage.Status != "complete") notes.Add("当前区间采集覆盖不完整，统计仅代表已记录数据；缺失时段不视为零事件，环比不计算。");
        if (oldCoverage.Status != "complete") notes.Add("上期采集覆盖不完整，无法给出可靠环比。");
        if (!equalDuration) notes.Add("当前周期与上期时长不同（例如月长不足），保留两期实际统计，但不计算同进度变化率。");
        return new(now, period, coverage, totals, comparison, trend, protocols, ports, sourceRows.Take(10).ToArray(),
            usernames, methods, risks, evidence, runtime, notes)
        {
            Regions = BuildRegions(sourceRows, invalidSources.FirstOrDefault(), totals),
        };
    }

    public static (ReportPeriod Period, DateTimeOffset PreviousStart, DateTimeOffset PreviousEnd) ResolvePeriod(ReportQuery query, DateTimeOffset now)
    {
        var kind = query.Period?.Trim().ToLowerInvariant() ?? "day";
        var local = now.ToOffset(TimeSpan.FromHours(8));
        DateTimeOffset start;
        DateTimeOffset end;
        DateTimeOffset previousStart;
        DateTimeOffset previousEnd;
        if (kind == "custom")
        {
            if (query.StartAtUtc is null || query.EndAtUtc is null) throw new ArgumentException("自定义报告必须提供带时区的开始和结束时间。");
            start = query.StartAtUtc.Value.ToUniversalTime();
            end = query.EndAtUtc.Value.ToUniversalTime();
            if (start >= end || end > now || end - start > TimeSpan.FromDays(366))
                throw new ArgumentException("报告区间必须为过去的有效半开区间，且不超过 366 天。");
            previousEnd = start;
            previousStart = start - (end - start);
            // 定时月报传完整自然月区间；上期应是前一个自然月，不能简单回退同样天数。
            var localStart = start.ToOffset(TimeSpan.FromHours(8));
            if (localStart.Day == 1 && localStart.TimeOfDay == TimeSpan.Zero && end == localStart.AddMonths(1))
                previousStart = localStart.AddMonths(-1);
        }
        else
        {
            if (query.StartAtUtc is not null || query.EndAtUtc is not null) throw new ArgumentException("仅自定义周期可传入起止时间。");
            var midnight = new DateTimeOffset(local.Date, local.Offset);
            start = kind switch
            {
                "day" => midnight,
                "week" => midnight.AddDays(-(((int)local.DayOfWeek + 6) % 7)),
                "month" => new DateTimeOffset(local.Year, local.Month, 1, 0, 0, 0, local.Offset),
                _ => throw new ArgumentException("报告周期只支持 day、week、month、custom。"),
            };
            end = now;
            previousStart = kind switch { "day" => start.AddDays(-1), "week" => start.AddDays(-7), _ => start.AddMonths(-1) };
            previousEnd = previousStart + (end - start);
            if (previousEnd > start) previousEnd = start;
        }
        // UTC 存储，只有自然周期边界按 Asia/Shanghai 解释。
        return (new(kind, "Asia/Shanghai", start.ToUniversalTime(), end.ToUniversalTime(),
            end - start <= TimeSpan.FromDays(2) ? "hour" : "day", kind != "custom"),
            previousStart.ToUniversalTime(), previousEnd.ToUniversalTime());
    }

    private static IQueryable<ReportEventEntity> Facts(HoneypotDbContext db, long start, long end) =>
        db.Set<ReportEventEntity>().AsNoTracking().Where(item => item.OccurredAtUnixMs >= start && item.OccurredAtUnixMs < end);

    private static async Task<ReportTotals> TotalsAsync(HoneypotDbContext db, long start, long end, CancellationToken ct)
    {
        var facts = Facts(db, start, end);
        var count = await facts.LongCountAsync(ct);
        var hasSamples = await db.Set<ReportRuntimeSampleEntity>().AnyAsync(item => item.CapturedAtUnixMs >= start && item.CapturedAtUnixMs < end || item.CoverageStartAtUnixMs < end && item.CapturedAtUnixMs > start, ct);
        if (count == 0 && !hasSamples) return new(null, null, null, null, null, null, null, null, null, null);
        var aggregate = await facts.GroupBy(_ => 1).Select(group => new
        {
            Connections = group.LongCount(item => item.EventType == "connectionaccepted"),
            Attempts = group.LongCount(item => item.EventType == "authenticationattempted"),
            Failures = group.LongCount(item => item.IsAuthenticationFailure),
            Violations = group.LongCount(item => item.EventType == "protocolviolation"),
            Truncated = group.LongCount(item => item.CaptureTruncated),
            Closed = group.LongCount(item => item.EventType == "sessionclosed"),
        }).SingleOrDefaultAsync(ct);
        var ips = await facts.Where(item => item.SourceIp != "").Select(item => item.SourceIp).Distinct().LongCountAsync(ct);
        var newIps = await db.Set<ReportSourceFirstSeenEntity>().LongCountAsync(item => item.FirstSeenAtUnixMs >= start && item.FirstSeenAtUnixMs < end, ct);
        var artifacts = await facts.Where(item => item.CredentialArtifactId != null).Select(item => item.CredentialArtifactId).Distinct().LongCountAsync(ct);
        return new(count, aggregate?.Connections ?? 0, ips, newIps, aggregate?.Attempts ?? 0, aggregate?.Failures ?? 0,
            aggregate?.Violations ?? 0, artifacts, aggregate?.Truncated ?? 0, aggregate?.Closed ?? 0);
    }

    private static async Task<ReportCoverage> CoverageAsync(HoneypotDbContext db, long start, long end, CancellationToken ct)
    {
        // 对区间求并集；时钟回拨或重复/重叠采样不能填平真正缺失的采集时段。
        var coverageRows = await db.Database.SqlQuery<long>($"""
            WITH spans AS (
                SELECT MAX("CoverageStartAtUnixMs", {start}) AS s, MIN("CapturedAtUnixMs", {end}) AS e
                FROM report_runtime_samples
                WHERE "CapturedAtUnixMs" > {start} AND "CoverageStartAtUnixMs" < {end}
                  AND "CapturedAtUnixMs" > "CoverageStartAtUnixMs" AND "PersistenceFailures" = 0
            ), ordered AS (
                SELECT s, e, MAX(e) OVER (ORDER BY s, e ROWS BETWEEN UNBOUNDED PRECEDING AND 1 PRECEDING) AS previousEnd
                FROM spans
            )
            SELECT COALESCE(SUM(MAX(0, e - MAX(s, COALESCE(previousEnd, s)))), 0) AS Value FROM ordered
            """).ToListAsync(ct);
        var coveredMs = coverageRows.Single();
        var samples = db.Set<ReportRuntimeSampleEntity>().Where(item => item.CapturedAtUnixMs >= start && item.CapturedAtUnixMs < end);
        var first = await samples.MinAsync(item => (long?)item.CapturedAtUnixMs, ct);
        var last = await samples.MaxAsync(item => (long?)item.CapturedAtUnixMs, ct);
        var failures = await samples.SumAsync(item => (long?)item.PersistenceFailures, ct) ?? 0;
        var duration = Math.Max(0, end - start);
        coveredMs = Math.Clamp(coveredMs, 0, duration);
        var unknown = duration - coveredMs;
        var hasEvents = await Facts(db, start, end).AnyAsync(ct);
        return new(coveredMs == 0 ? "unknown" : unknown == 0 && failures == 0 ? "complete" : "partial",
            coveredMs / 1000d, unknown / 1000d, duration > 0 ? Math.Round(100d * coveredMs / duration, 2) : 0,
            At(first), At(last), failures, hasEvents);
    }

    private static async Task<List<ReportBreakdown>> BreakdownAsync(IQueryable<ReportEventEntity> facts,
        Expression<Func<ReportEventEntity, string>> key, int limit, CancellationToken ct) =>
        await facts.GroupBy(key).Select(group => new
        {
            Key = group.Key, Events = group.LongCount(), Connections = group.LongCount(item => item.EventType == "connectionaccepted"),
            AuthenticationFailures = group.LongCount(item => item.IsAuthenticationFailure),
            SourceIps = group.Where(item => item.SourceIp != "").Select(item => item.SourceIp).Distinct().LongCount(),
        }).OrderByDescending(item => item.Events).ThenBy(item => item.Key).Take(limit)
            .Select(item => new ReportBreakdown(item.Key, item.Events, item.Connections, item.AuthenticationFailures, item.SourceIps)).ToListAsync(ct);

    private static async Task<IReadOnlyList<ReportTrendPoint>> TrendAsync(HoneypotDbContext db, IQueryable<ReportEventEntity> facts,
        long start, long end, long width, CancellationToken ct)
    {
        var values = await facts.GroupBy(item => (item.OccurredAtUnixMs - start) / width).Select(group => new
        {
            Index = group.Key, Events = group.LongCount(), Connections = group.LongCount(item => item.EventType == "connectionaccepted"),
            Failures = group.LongCount(item => item.IsAuthenticationFailure), Violations = group.LongCount(item => item.EventType == "protocolviolation"),
        }).ToDictionaryAsync(item => item.Index, ct);
        // 按趋势桶拆分后分别取区间并集；正常心跳最多拆两段，补充样本跨更多桶也能正确处理。
        var coverages = await db.Database.SqlQuery<TrendCoverageBucket>($"""
            WITH RECURSIVE spans AS (
                SELECT MAX("CoverageStartAtUnixMs", {start}) AS s, MIN("CapturedAtUnixMs", {end}) AS e
                FROM report_runtime_samples
                WHERE "CapturedAtUnixMs" > {start} AND "CoverageStartAtUnixMs" < {end}
                  AND "CapturedAtUnixMs" > "CoverageStartAtUnixMs" AND "PersistenceFailures" = 0
            ), parts(Bucket, s, e, endAt) AS (
                SELECT ((s - {start}) / {width}) AS Bucket,
                       s, MIN(e, {start} + (((s - {start}) / {width}) + 1) * {width}), e
                FROM spans
                UNION ALL
                SELECT Bucket + 1, e, MIN(endAt, {start} + (Bucket + 2) * {width}), endAt
                FROM parts WHERE e < endAt
            ), ordered AS (
                SELECT Bucket, s, e,
                       MAX(e) OVER (PARTITION BY Bucket ORDER BY s, e ROWS BETWEEN UNBOUNDED PRECEDING AND 1 PRECEDING) AS previousEnd
                FROM parts
            )
            SELECT Bucket, SUM(MAX(0, e - MAX(s, COALESCE(previousEnd, s)))) AS CoveredMs FROM ordered GROUP BY Bucket
            """).ToDictionaryAsync(item => item.Bucket, ct);
        var result = new List<ReportTrendPoint>();
        for (long index = 0; start + index * width < end; index++)
        {
            values.TryGetValue(index, out var value);
            coverages.TryGetValue(index, out var coverage);
            var covered = coverage?.CoveredMs ?? 0;
            var duration = Math.Min(width, end - (start + index * width));
            var status = covered == 0 ? "unknown" : covered >= duration ? "complete" : "partial";
            var observed = covered > 0 || value is not null;
            result.Add(new(DateTimeOffset.FromUnixTimeMilliseconds(start + index * width), observed ? value?.Events ?? 0 : null,
                observed ? value?.Connections ?? 0 : null, observed ? value?.Failures ?? 0 : null,
                observed ? value?.Violations ?? 0 : null, status));
        }
        return result;
    }

    private sealed class TrendCoverageBucket
    {
        public long Bucket { get; set; }
        public long CoveredMs { get; set; }
    }

    private static async Task<ReportRuntime> RuntimeAsync(HoneypotDbContext db, long start, long end, CancellationToken ct)
    {
        var samples = db.Set<ReportRuntimeSampleEntity>().AsNoTracking().Where(item => item.CapturedAtUnixMs >= start && item.CapturedAtUnixMs < end);
        var aggregate = await samples.GroupBy(_ => 1).Select(group => new
        {
            Count = group.LongCount(), AverageCpu = group.Average(item => item.ProcessCpuPercent), PeakCpu = group.Max(item => item.ProcessCpuPercent),
            AverageMemory = group.Average(item => (double)item.ProcessMemoryBytes), PeakMemory = group.Max(item => item.ProcessMemoryBytes),
            PeakConnections = group.Max(item => item.ActiveConnections), AverageRunning = group.Average(item => (double)item.RunningListeners),
            PeakFailed = group.Max(item => item.FailedListeners),
            Normal = group.LongCount(item => item.ConfiguredListeners > 0 && item.RunningListeners == item.ConfiguredListeners && item.FailedListeners == 0),
            Eligible = group.LongCount(item => item.ConfiguredListeners > 0), MinimumDisk = group.Min(item => item.DataDiskFreeBytes),
        }).SingleOrDefaultAsync(ct);
        var last = await samples.OrderByDescending(item => item.CapturedAtUnixMs).FirstOrDefaultAsync(ct);
        if (aggregate is null) return new(0, null, null, null, null, null, null, null, null, null, null);
        return new(aggregate.Count, aggregate.AverageCpu, aggregate.PeakCpu, (long)aggregate.AverageMemory, aggregate.PeakMemory,
            aggregate.PeakConnections, aggregate.AverageRunning, aggregate.PeakFailed, last?.ConfiguredListeners,
            aggregate.Eligible > 0 ? Math.Round(100d * aggregate.Normal / aggregate.Eligible, 2) : null,
            At(last?.CapturedAtUnixMs), last?.DataDiskFreeBytes, aggregate.MinimumDisk);
    }

    private IReadOnlyList<ReportBreakdown> BuildRegions(IReadOnlyList<ReportBreakdown> sources, ReportBreakdown? invalidSources, ReportTotals totals)
    {
        var result = locationResolver?.Resolve(sources.Select(item => item.Key).ToArray());
        var locations = result?.Items.ToDictionary(item => item.Ip) ?? [];
        var grouped = sources.GroupBy(item =>
        {
            if (!locations.TryGetValue(item.Key, out var location)) return "未知/未启用";
            if (location.Status == "resolved") return string.Join(" / ", new[] { location.Country, location.Province }.Where(value => value.Length > 0)) is { Length: > 0 } region ? region : "已解析/地区未知";
            return location.Status switch { "private" => "内网地址", "reserved" => "保留地址", "disabled" => "未启用解析", "pending" => "待解析", "busy" => "待解析", _ => "未知" };
        }).Select(group => new ReportBreakdown(group.Key, group.Sum(item => item.Events), group.Sum(item => item.Connections),
            group.Sum(item => item.AuthenticationFailures), group.Sum(item => item.SourceIps))).ToList();
        var rest = (totals.UniqueSourceIps ?? 0) - sources.Count;
        if (rest > 0) grouped.Add(new("其他来源/未解析", Math.Max(0, (totals.EventCount ?? 0) - sources.Sum(item => item.Events) - (invalidSources?.Events ?? 0)),
            Math.Max(0, (totals.AcceptedConnections ?? 0) - sources.Sum(item => item.Connections) - (invalidSources?.Connections ?? 0)),
            Math.Max(0, (totals.AuthenticationFailures ?? 0) - sources.Sum(item => item.AuthenticationFailures) - (invalidSources?.AuthenticationFailures ?? 0)), rest));
        if (invalidSources is not null) grouped.Add(invalidSources);
        return grouped.OrderByDescending(item => item.Events).ToArray();
    }

    private static DateTimeOffset? At(long? value) => value is { } ms ? DateTimeOffset.FromUnixTimeMilliseconds(ms) : null;
    private static double? Change(long? current, long? previous) => current is { } value && previous is > 0
        ? Math.Round(100d * (value - previous.Value) / previous.Value, 2) : null;
}
