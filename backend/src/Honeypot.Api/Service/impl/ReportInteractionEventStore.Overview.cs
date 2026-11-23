using Honeypot.Api.Common;
using Honeypot.Api.Data;
using Honeypot.Api.Data.Models;
using Microsoft.Data.Sqlite;
using Honeypot.Api.Models;
using Microsoft.EntityFrameworkCore;

namespace Honeypot.Api.Service.impl;

public sealed partial class ReportInteractionEventStore
{
    internal OverviewEventStatistics ReadOverviewStatistics(DateTimeOffset now, bool includeActivityCoverage = false,
        CancellationToken cancellationToken = default)
    {
        using var db = OpenReadContext();
        db.Database.OpenConnection();
        using var read = ((SqliteConnection)db.Database.GetDbConnection()).BeginTransaction(deferred: true);
        using var contextTransaction = db.Database.UseTransaction(read);
        var start = now.AddHours(-24);
        var from = start.ToUnixTimeMilliseconds();
        var end = now.ToUnixTimeMilliseconds();
        var local = now.ToOffset(TimeSpan.FromHours(8));
        var midnight = new DateTimeOffset(local.Date, local.Offset).ToUnixTimeMilliseconds();
        var firstHour = OverviewActivityProjection.HourWindow(now).Start;
        var hourStart = firstHour.ToUnixTimeMilliseconds();
        const int hourMs = 3_600_000;
        var trendStart = Math.Max(hourStart, now.AddDays(-_options.ReportRetentionDays).ToUnixTimeMilliseconds());
        var groups = ReadFactGroups(db, from, end, hourStart, trendStart, cancellationToken);
        var coverage = includeActivityCoverage
            ? SqliteReportService.TrendCoverage(db, hourStart, end, trendStart, hourMs).ToDictionary(row => row.Bucket, row => row.CoveredMs)
            : null;
        // 旧版本可能只有报告事实。卡片、协议活动和下钻以实际连接摘要及尚可追溯的认证/异常为准。
        // 将两个窄时间范围合并后再去重来源；不会把不同时段的独立 IP 数相加。
        // connection_summaries 是普通 rowid 表。先从接纳时间索引取行号，再按行号访问摘要，减少乱序回表。
        var detailCutoff = _time.GetUtcNow().AddDays(-_options.DetailRetentionDays).ToUnixTimeMilliseconds();
        var midnightTicks = DateTimeOffset.FromUnixTimeMilliseconds(midnight).UtcTicks;
        var trace = db.Database.SqlQuery<TraceCounts>($"""
            WITH trace(Adapter,Ip,Ticks,Accepts,Attempts,Failures,Violations) AS (
                SELECT lower(trim(AdapterKey)),SourceIp,AdmittedAtUtcTicks,1,0,0,0
                FROM connection_summaries WHERE rowid IN (
                    SELECT rowid FROM connection_summaries WHERE AdmissionOutcome='accepted'
                        AND AdmittedAtUtcTicks BETWEEN {start.UtcTicks} AND {now.UtcTicks}
                ) AND LastReceivedAtUnixMs>{detailCutoff}
                UNION ALL
                SELECT f.AdapterKey,e.SourceIp,e.OccurredAtUtcTicks,0,(f.EventType='authenticationattempted'),
                    f.IsAuthenticationFailure,(f.EventType='protocolviolation')
                FROM report_events f JOIN interaction_events e ON e.EventId=f.EventId
                WHERE f.EventType IN ('authenticationattempted','protocolviolation') AND f.OccurredAtUnixMs BETWEEN {from} AND {end}
                    AND e.OccurredAtUtcTicks BETWEEN {start.UtcTicks} AND {now.UtcTicks} AND e.ReceivedAtUnixMs>{detailCutoff}
            )
            SELECT Adapter,SUM(Accepts) AS Accepts,SUM(Attempts) AS Attempts,SUM(Failures) AS Failures,
                SUM(CASE WHEN Ticks>={midnightTicks} THEN Failures ELSE 0 END) AS TodayFailures,SUM(Violations) AS Violations,
                SUM(CASE WHEN Ticks>={firstHour.UtcTicks} THEN Accepts ELSE 0 END) AS HourAccepts,
                SUM(CASE WHEN Ticks>={firstHour.UtcTicks} THEN Failures ELSE 0 END) AS HourFailures,
                SUM(CASE WHEN Ticks>={firstHour.UtcTicks} THEN Violations ELSE 0 END) AS HourViolations,
                COUNT(DISTINCT CASE WHEN Ticks>={firstHour.UtcTicks} AND Accepts+Failures+Violations>0 AND Ip NOT IN ('','unknown') THEN Ip END) AS Sources,
                MAX(CASE WHEN Ticks>={firstHour.UtcTicks} AND Accepts+Failures+Violations>0 THEN Ticks END) AS LastTicks
            FROM trace GROUP BY Adapter
            """).ToArray();
        var hours = groups.Where(row => row.Start >= hourStart).ToLookup(row => (row.Start - hourStart) / hourMs);
        var byHour = new List<MetricBucket>(24);
        var activity = new List<HourlyActivityMetric>(24);
        for (var index = 0; index < 24; index++)
        {
            var hour = firstHour.AddHours(index);
            var bucket = hours[index];
            var label = OverviewActivityProjection.FormatHour(hour);
            byHour.Add(new(label, bucket.Sum(row => row.Count)));
            if (coverage is null)
            {
                activity.Add(new(label, bucket.Sum(row => row.Accepts), bucket.Sum(row => row.Failures)));
                continue;
            }
            // 报表趋势是半开区间。没有心跳和事件的小时显示缺测，整点所在的新小时同样缺测。
            var eligible = bucket.Where(row => row.Start >= trendStart && row.Start < end).ToArray();
            var coveredMs = coverage.GetValueOrDefault(index);
            var observed = coveredMs > 0 || eligible.Length > 0;
            activity.Add(new(label, observed ? eligible.Sum(row => row.Accepts) : null,
                observed ? eligible.Sum(row => row.Failures) : null)
            {
                CoverageStatus = SqliteReportService.CoverageStatus(coveredMs, Math.Min(hourMs, end - hour.ToUnixTimeMilliseconds()))
            });
        }
        var adapters = trace.Where(row => row.LastTicks.HasValue && OverviewActivityProjection.NamedValue(row.Adapter) != null)
            .Select(row => new AdapterActivityMetric(row.Adapter,row.HourAccepts,row.HourFailures,row.Sources,row.HourViolations,
                new DateTimeOffset(row.LastTicks!.Value,TimeSpan.Zero)))
            .OrderByDescending(row => row.AuthenticationFailures).ThenByDescending(row => row.AcceptedConnections).ThenBy(row => row.AdapterKey).ToArray();
        var known = groups.Where(row => row.Outcome != "").ToArray();
        var byAdapter = known.GroupBy(row => row.Adapter == "" ? "unknown" : row.Adapter)
            .Select(group => new MetricBucket(group.Key, group.Sum(row => row.Count))).OrderByDescending(row => row.Count)
            .ThenBy(row => row.Key, StringComparer.Ordinal).ToArray();
        var byOutcome = known.GroupBy(row => row.Outcome)
            .Select(group => new MetricBucket(group.Key, group.Sum(row => row.Count))).OrderByDescending(row => row.Count)
            .ThenBy(row => row.Key, StringComparer.Ordinal).ToArray();
        return new(known.Sum(row => row.Count), trace.Sum(row => row.Accepts), trace.Sum(row => row.Attempts),
            trace.Sum(row => row.Failures), trace.Sum(row => row.TodayFailures), trace.Sum(row => row.Violations),
            known.Sum(row => row.Closed), byAdapter, byOutcome, byHour, adapters, activity)
        {
            ReportOnlyEvents = groups.Where(row => row.Outcome == "").Sum(row => row.Count),
            TraceableThreats = db.Set<ThreatProfileEntity>().Count(profile => profile.ExpiresAtUnixMs > end &&
                db.Set<ConnectionSummaryEntity>().Any(row => row.SourceIp == profile.SourceIp && row.LastReceivedAtUnixMs > detailCutoff &&
                    (row.AdmittedAtUtcTicks ?? row.RepresentativeUtcTicks) <= now.UtcTicks))
        };
    }

    private sealed record FactCounts(long Start, string Adapter, string Outcome, int Count, int Closed, int Accepts, int Failures);

    private static List<FactCounts> ReadFactGroups(HoneypotDbContext db, long from, long end, long firstHour, long trendStart,
        CancellationToken cancellationToken)
    {
        // 分段走既有时间索引，每条事实只进入一个小分组；卡片含截止毫秒，报表趋势单独排除这一毫秒。
        var boundaries = new SortedSet<long> { from, end, end + 1 };
        for (var hour = firstHour; hour < end; hour += 3_600_000) boundaries.Add(hour);
        if (trendStart > from && trendStart < end) boundaries.Add(trendStart);
        var result = new List<FactCounts>();
        var start = from;
        foreach (var next in boundaries)
        {
            if (next <= start) continue;
            cancellationToken.ThrowIfCancellationRequested();
            result.AddRange(db.Database.SqlQuery<FactCounts>($"""
                SELECT {start} AS Start, AdapterKey AS Adapter, Outcome, COUNT(*) AS Count,
                    COUNT(*) FILTER (WHERE EventType='sessionclosed') AS Closed,
                    COUNT(*) FILTER (WHERE EventType='connectionaccepted') AS Accepts,
                    COUNT(*) FILTER (WHERE IsAuthenticationFailure) AS Failures
                FROM report_events WHERE OccurredAtUnixMs >= {start} AND OccurredAtUnixMs < {next} GROUP BY AdapterKey, Outcome
                """));
            start = next;
        }
        return result;
    }

    private sealed record TraceCounts(string Adapter, int Accepts, int Attempts, int Failures, int TodayFailures, int Violations,
        int HourAccepts, int HourFailures, int HourViolations, int Sources, long? LastTicks);

    internal IReadOnlyList<OverviewConnectionRow> ReadMapConnections(DateTimeOffset from, DateTimeOffset now)
    {
        using var db = OpenReadContext();
        return db.Set<ConnectionSummaryEntity>().AsNoTracking()
            .Where(row => row.AdmissionOutcome == "accepted" && row.AdmittedAtUtcTicks >= from.UtcTicks && row.AdmittedAtUtcTicks <= now.UtcTicks)
            .OrderByDescending(row => row.AdmittedAtUtcTicks).ThenBy(row => row.AdmissionEventId)
            .Select(row => new OverviewConnectionRow(row.AdmissionEventId!, row.ConnectionId,
                new DateTimeOffset(row.AdmittedAtUtcTicks!.Value, TimeSpan.Zero), row.SourceIp, row.SourcePort, row.AdapterKey, row.DestinationPort)).ToArray();
    }
}
