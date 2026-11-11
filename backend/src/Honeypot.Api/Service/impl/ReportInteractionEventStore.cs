using System.Data.Common;
using System.Net;
using Honeypot.Api.Data;
using Honeypot.Api.Data.Models;
using Honeypot.Protocol.Abstractions.Models;
using Honeypot.Protocols.Common;
using Honeypot.Shared.Models;
using Microsoft.EntityFrameworkCore;

namespace Honeypot.Api.Service.impl;

/// <summary>先可靠保存报告事实，再转交原事件存储；SMTP 和报表计算不进入协议采集路径。</summary>
public sealed class ReportInteractionEventStore(
    IDbContextFactory<HoneypotDbContext> factory,
    InMemoryInteractionEventStore inner,
    ReportIngestionHealth health,
    ILogger<ReportInteractionEventStore> logger,
    ISyslogPublisher? logs = null) : IInteractionEventStore, ICredentialEvidenceSink
{
    // SQLite 单机写入串行化，也保证新来源与事实在同一事务内一致。
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private int _consecutiveFailures;

    public async ValueTask<EventAppendResult> AppendAsync(InteractionEvent interactionEvent, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(interactionEvent.EventId) || interactionEvent.EventId.Length > 128)
        {
            health.RecordFailure();
            return EventAppendResult.DegradedResult("REPORT_INVALID_EVENT_ID", "事件标识不符合持久化约定。");
        }
        await _writeLock.WaitAsync(cancellationToken);
        try
        {
            await using var db = await factory.CreateDbContextAsync(cancellationToken);
            if (await db.Set<ReportEventEntity>().AnyAsync(item => item.EventId == interactionEvent.EventId, cancellationToken))
                return EventAppendResult.Duplicate("duplicate report event ignored");

            await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
            var fact = Project(interactionEvent);
            db.Set<ReportEventEntity>().Add(fact);
            if (fact.SourceIp.Length > 0)
            {
                var first = await db.Set<ReportSourceFirstSeenEntity>().FindAsync([fact.SourceIp], cancellationToken);
                if (first is null)
                    db.Set<ReportSourceFirstSeenEntity>().Add(new() { SourceIp = fact.SourceIp, FirstSeenAtUnixMs = fact.OccurredAtUnixMs });
                else if (fact.OccurredAtUnixMs < first.FirstSeenAtUnixMs)
                    first.FirstSeenAtUnixMs = fact.OccurredAtUnixMs;
            }
            await db.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            var result = await inner.AppendAsync(interactionEvent, cancellationToken);
            if (result.Recorded)
            {
                if (_consecutiveFailures >= 3)
                    logs?.Publish("honeypot-events", "EVENT_PERSISTENCE_RECOVERED", SyslogSeverity.Notice,
                        new Dictionary<string, object?> { ["failureCount"] = _consecutiveFailures });
                _consecutiveFailures = 0;
            }
            return result;
        }
        catch (Exception error) when (error is DbException or DbUpdateException or IOException or InvalidOperationException)
        {
            health.RecordFailure();
            // 不输出异常正文/参数，以免驱动附带不可信事件字段。
            logger.LogError("Report event persistence failed; the event was not accepted. EventId={EventId} ErrorCode={ErrorCode} FailureCount={FailureCount}",
                interactionEvent.EventId, "REPORT_PERSISTENCE_FAILED", health.PersistenceFailures);
            if (++_consecutiveFailures == 3)
                logs?.Publish("honeypot-events", "EVENT_PERSISTENCE_UNAVAILABLE", SyslogSeverity.Critical,
                    new Dictionary<string, object?> { ["failureCount"] = _consecutiveFailures, ["errorCode"] = "REPORT_PERSISTENCE_FAILED" });
            return EventAppendResult.DegradedResult("REPORT_PERSISTENCE_FAILED", "报告事件持久化失败，未确认接收。");
        }
        finally { _writeLock.Release(); }
    }

    public IReadOnlyCollection<InteractionEvent> GetAll() => inner.GetAll();
    public IReadOnlyCollection<InteractionEvent> GetByConnectionId(string connectionId) => inner.GetByConnectionId(connectionId);
    public ValueTask<string> StoreAsync(CredentialEvidence evidence, CancellationToken cancellationToken = default) =>
        inner.StoreAsync(evidence, cancellationToken);

    internal static ReportEventEntity Project(InteractionEvent value)
    {
        var eventType = Safe(value.EventType, 64).ToLowerInvariant();
        var source = IPAddress.TryParse(value.SourceIp, out var ip) ? (ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4() : ip).ToString() : "";
        var artifact = Safe(value.CredentialArtifactId, 128);
        return new()
        {
            EventId = value.EventId,
            OccurredAtUnixMs = value.OccurredAtUtc.ToUnixTimeMilliseconds(),
            EventType = eventType,
            SourceIp = source,
            AdapterKey = Safe(value.AdapterKey, 64).ToLowerInvariant(),
            DestinationPort = value.DestinationPort is >= 1 and <= 65535 ? value.DestinationPort : 0,
            Username = eventType == "authenticationattempted" ? Safe(value.Username, 128) : "",
            AuthenticationMethod = eventType == "authenticationattempted" ? Safe(value.AuthenticationMethod, 64) : "",
            IsAuthenticationFailure = eventType == "authenticationattempted" &&
                new[] { "failure", "rejected", "invalid" }.Contains(value.Outcome?.Trim(), StringComparer.OrdinalIgnoreCase),
            RiskSignal = value.RiskDelta >= 10 ? "high" : value.RiskDelta >= 5 ? "medium" : value.RiskDelta > 0 ? "low" : "none",
            EvidenceKind = artifact.Length > 0 ? Safe(value.MaterialType, 64) is { Length: > 0 } kind ? kind : "collected" : "none",
            CredentialArtifactId = artifact.Length > 0 ? artifact : null,
            CaptureTruncated = value.CaptureTruncated,
        };
    }

    private static string Safe(string? value, int limit) => string.IsNullOrWhiteSpace(value) ? "" :
        new string(value.Trim().Where(character => !char.IsControl(character)).Take(limit).ToArray());
}
