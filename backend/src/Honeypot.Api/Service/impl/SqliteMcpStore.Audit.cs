using System.Text.Json;
using Honeypot.Api.Data;
using Honeypot.Api.Data.Models;
using Honeypot.Api.Models;
using Microsoft.EntityFrameworkCore;

namespace Honeypot.Api.Service.impl;

public sealed partial class SqliteMcpStore
{
    private static readonly TimeSpan PendingTimeout = TimeSpan.FromMinutes(2);
    private const long MillisecondsPerDay = 86_400_000;

    public Task<string> BeginAuditAsync(McpAuditEntry entry, CancellationToken cancellationToken = default) =>
        InsertAuditAsync(entry with { Result = McpAuditResult.Pending }, cancellationToken);

    public async Task RecordAuditAsync(McpAuditEntry entry, CancellationToken cancellationToken = default) =>
        await InsertAuditAsync(entry, cancellationToken);

    private async Task<string> InsertAuditAsync(McpAuditEntry entry, CancellationToken cancellationToken)
    {
        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
        var row = new McpCallAuditEntity
        {
            Id = ids.NewId(), OccurredUnixMs = entry.OccurredAtUtc.ToUnixTimeMilliseconds(),
            HttpMethod = entry.HttpMethod, Result = entry.Result, DetailsJson = "",
        };
        SetAuditData(row, entry);
        db.Add(row);
        await db.SaveChangesAsync(cancellationToken);
        return row.Id;
    }

    public async Task CompleteAuditAsync(string id, McpAuditEntry entry, CancellationToken cancellationToken = default)
    {
        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
        var row = await db.Set<McpCallAuditEntity>().SingleAsync(item => item.Id == id && item.Result == McpAuditResult.Pending,
            cancellationToken);
        SetAuditData(row, entry);
        await db.SaveChangesAsync(cancellationToken);
    }

    public async Task<McpPage<McpAuditSummary>> GetAuditsAsync(McpAuditFilter filter, CancellationToken cancellationToken)
    {
        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
        var now = clock.GetUtcNow();
        var pendingSince = now.Subtract(PendingTimeout).ToUnixTimeMilliseconds();
        var cutoff = RetentionCutoff(db, now);
        var query = db.Set<McpCallAuditEntity>().AsNoTracking().Where(row => row.OccurredUnixMs > cutoff.First());
        if (filter.KeyId is { } keyId) query = query.Where(row => row.KeyId == keyId);
        if (filter.Tool is { } tool) query = query.Where(row => row.Tool == tool);
        if (filter.SourceIp is { } source) query = query.Where(row => row.SourceIp == source);
        if (filter.FromUtc is { } from)
        {
            var milliseconds = from.ToUnixTimeMilliseconds();
            query = query.Where(row => row.OccurredUnixMs >= milliseconds);
        }
        if (filter.ToUtc is { } to)
        {
            var milliseconds = to.ToUnixTimeMilliseconds();
            query = query.Where(row => row.OccurredUnixMs < milliseconds);
        }
        query = filter.Result switch
        {
            McpAuditResult.Unknown => query.Where(row => row.Result == McpAuditResult.Unknown ||
                (row.Result == McpAuditResult.Pending && row.OccurredUnixMs <= pendingSince)),
            McpAuditResult.Pending => query.Where(row => row.Result == McpAuditResult.Pending && row.OccurredUnixMs > pendingSince),
            { } result => query.Where(row => row.Result == result),
            _ => query,
        };
        var total = await query.CountAsync(cancellationToken);
        // 列表只读取索引字段和摘要，不从 SQLite 拉取大体积的请求与响应正文。
        var rows = await query.OrderByDescending(row => row.OccurredUnixMs).ThenByDescending(row => row.Id)
            .Skip((filter.Page - 1) * filter.PageSize).Take(filter.PageSize)
            .Select(row => new McpCallAuditEntity
            {
                Id = row.Id, OccurredUnixMs = row.OccurredUnixMs, KeyId = row.KeyId, KeyName = row.KeyName,
                KeyPrefix = row.KeyPrefix, Tool = row.Tool, SourceIp = row.SourceIp, HttpMethod = row.HttpMethod, McpMethod = row.McpMethod,
                HttpStatus = row.HttpStatus, Result = row.Result, DurationMs = row.DurationMs, DetailsJson = "",
            }).ToListAsync(cancellationToken);
        return new(rows.Select(row => ToAuditSummary(row, pendingSince)).ToArray(), total, filter.Page, filter.PageSize);
    }

    public async Task<McpAuditDetails?> GetAuditAsync(string id, CancellationToken cancellationToken)
    {
        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
        var now = clock.GetUtcNow();
        var cutoff = RetentionCutoff(db, now);
        var row = await db.Set<McpCallAuditEntity>().AsNoTracking()
            .SingleOrDefaultAsync(row => row.Id == id && row.OccurredUnixMs > cutoff.First(), cancellationToken);
        if (row is null) return null;
        var data = JsonSerializer.Deserialize<McpAuditEntry>(row.DetailsJson, Json)
            ?? throw new InvalidOperationException("MCP audit details are unavailable.");
        var summary = ToAuditSummary(row, now.Subtract(PendingTimeout).ToUnixTimeMilliseconds());
        return new(summary.Id, summary.OccurredAtUtc, summary.KeyId, summary.KeyName, summary.KeyPrefix, summary.Tool,
            summary.SourceIp, summary.HttpMethod, summary.McpMethod, summary.HttpStatus, summary.Result, summary.DurationMs, data.Path,
            data.ClientName, data.ProtocolVersion, data.RequestId, data.TraceId, data.ErrorCode, data.ErrorMessage,
            data.RequestBytes, data.ResponseBytes, data.RequestHeaders, data.RequestParameters, data.ResponseHeaders, data.ResponseBody,
            data.CaptureNote, data.RequestBodyOmittedReason, data.ResponseBodyOmittedReason);
    }

    public async Task<int> DeleteExpiredAuditsAsync(int maximum, CancellationToken cancellationToken)
    {
        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
        var cutoff = RetentionCutoff(db, clock.GetUtcNow());
        var rows = db.Set<McpCallAuditEntity>();
        // 在删除语句中读取生效留存，避免同时调长留存时仍使用过时的截止时间。
        var batch = rows.Where(row => row.OccurredUnixMs <= cutoff.First())
            .OrderBy(row => row.OccurredUnixMs).ThenBy(row => row.Id).Take(maximum).Select(row => row.Id);
        return await rows.Where(row => batch.Contains(row.Id)).ExecuteDeleteAsync(cancellationToken);
    }

    private static IQueryable<long> RetentionCutoff(HoneypotDbContext db, DateTimeOffset now)
    {
        var utcMillis = now.ToUnixTimeMilliseconds();
        return SettingsQuery(db).Select(row => utcMillis - row.AuditRetentionDays * MillisecondsPerDay);
    }

    private static void SetAuditData(McpCallAuditEntity row, McpAuditEntry entry)
    {
        row.KeyId = entry.KeyId;
        row.KeyName = entry.KeyName;
        row.KeyPrefix = entry.KeyPrefix;
        row.Tool = entry.ToolName;
        row.McpMethod = entry.McpMethod;
        row.SourceIp = entry.SourceIp;
        row.HttpStatus = entry.HttpStatus;
        row.Result = entry.Result;
        row.DurationMs = entry.ElapsedMs;
        row.DetailsJson = JsonSerializer.Serialize(entry, Json);
    }

    private static McpAuditSummary ToAuditSummary(McpCallAuditEntity row, long pendingSince) =>
        new(row.Id, DateTimeOffset.FromUnixTimeMilliseconds(row.OccurredUnixMs), row.KeyId, row.KeyName, row.KeyPrefix, row.Tool,
            row.SourceIp, row.HttpMethod, row.McpMethod, row.HttpStatus,
            row.Result == McpAuditResult.Pending && row.OccurredUnixMs <= pendingSince ? McpAuditResult.Unknown : row.Result, row.DurationMs);
}
