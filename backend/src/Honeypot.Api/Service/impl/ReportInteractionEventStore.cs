using System.Net;
using System.Text;
using System.Threading.Channels;
using Honeypot.Api.Common;
using Honeypot.Api.Data;
using Honeypot.Api.Data.Models;
using Honeypot.Api.Options;
using Honeypot.Protocol.Abstractions.Models;
using Honeypot.Protocols.Common;
using Honeypot.Shared.Models;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Honeypot.Api.Service.impl;

/// <summary>单队列接收事件，事务内更新报告、详情、威胁档案及密码簿依据。</summary>
public sealed partial class ReportInteractionEventStore(
    IDbContextFactory<HoneypotDbContext> factory,
    ICredentialEvidenceStore evidenceStore,
    SqliteThreatProfileStore threats,
    ReportIngestionHealth health,
    ILogger<ReportInteractionEventStore> logger,
    ISyslogPublisher? logs = null,
    IOptions<EventStorageOptions>? options = null,
    TimeProvider? time = null,
    ReportEventDiskBudget? diskBudget = null) : IInteractionEventStore, ICredentialEvidenceSink
{
    private readonly EventStorageOptions _options = options?.Value ?? new();
    private readonly TimeProvider _time = time ?? TimeProvider.System;
    private readonly ReportEventDiskBudget _diskBudget = diskBudget ?? new(time ?? TimeProvider.System);
    private readonly Channel<PendingEvent> _queue = Channel.CreateBounded<PendingEvent>(
        new BoundedChannelOptions((options?.Value ?? new EventStorageOptions()).QueueCapacity) { SingleReader = true });
    private int _consecutiveFailures;

    public async ValueTask<EventAppendResult> AppendAsync(InteractionEvent interactionEvent, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (string.IsNullOrWhiteSpace(interactionEvent.EventId) || interactionEvent.EventId.Length > 128 ||
            interactionEvent.EventId.Any(char.IsControl))
        {
            health.RecordRejectedEvent();
            return EventAppendResult.DegradedResult("REPORT_INVALID_EVENT_ID", "事件标识不符合持久化约定。");
        }

        // 排队满时立即返回，严禁排队外继续积压未受限的写入任务。
        var pending = new PendingEvent(InteractionEventSanitizer.Sanitize(interactionEvent), cancellationToken);
        health.ChangeQueueDepth(1);
        if (!_queue.Writer.TryWrite(pending))
        {
            health.ChangeQueueDepth(-1);
            health.RecordRejectedEvent();
            return EventAppendResult.DegradedResult("REPORT_EVENT_QUEUE_FULL", "事件写入队列已满或已停止。");
        }
        return await pending.Completion.Task.WaitAsync(cancellationToken);
    }

    internal void CompleteQueue() => _queue.Writer.TryComplete();

    internal async Task WriteQueuedEventsAsync(CancellationToken stoppingToken)
    {
        try
        {
            await foreach (var pending in _queue.Reader.ReadAllAsync(stoppingToken))
            {
                health.ChangeQueueDepth(-1);
                using var write = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken, pending.CancellationToken);
                try
                {
                    var result = await PersistAsync(pending.Event, write.Token);
                    pending.Completion.TrySetResult(result);
                }
                catch (OperationCanceledException) when (write.IsCancellationRequested)
                {
                    health.RecordRejectedEvent();
                    pending.Completion.TrySetCanceled(write.Token);
                }
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
        finally
        {
            CompleteQueue();
            while (_queue.Reader.TryRead(out var pending))
            {
                health.ChangeQueueDepth(-1);
                health.RecordRejectedEvent();
                pending.Completion.TrySetResult(EventAppendResult.DegradedResult("REPORT_EVENT_WRITER_STOPPED", "事件写入已停止。"));
            }
        }
    }

    private async Task<EventAppendResult> PersistAsync(InteractionEvent interactionEvent, CancellationToken cancellationToken)
    {
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            await using var db = await factory.CreateDbContextAsync(cancellationToken);
            // SQLite 驱动的异步调用可能同步等待锁，单条写入不能长时间占住唯一消费者。
            db.Database.SetCommandTimeout(2);
            if (db.Database.GetDbConnection() is SqliteConnection sqlite)
                sqlite.DefaultTimeout = 2;
            await db.Database.OpenConnectionAsync(cancellationToken);
            var fact = Project(interactionEvent);
            if (await db.Set<ReportEventEntity>().AnyAsync(item => item.EventId == interactionEvent.EventId, cancellationToken) ||
                await db.Set<InteractionEventEntity>().AnyAsync(item => item.EventId == interactionEvent.EventId, cancellationToken))
                return EventAppendResult.Duplicate();
            if (!await _diskBudget.CanWriteAsync(db, _options, health, cancellationToken))
                return Failed("REPORT_DISK_BUDGET_EXCEEDED", "报告数据库空间或可用磁盘空间已达限制。");

            await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
            var receivedAt = _time.GetUtcNow();
            db.Set<ReportEventEntity>().Add(fact);
            db.Set<InteractionEventEntity>().Add(InteractionEventEntity.FromSanitized(interactionEvent, receivedAt));
            if (fact.SourceIp.Length > 0)
            {
                var first = await db.Set<ReportSourceFirstSeenEntity>().FindAsync([fact.SourceIp], cancellationToken);
                if (first is null)
                    db.Set<ReportSourceFirstSeenEntity>().Add(new() { SourceIp = fact.SourceIp, FirstSeenAtUnixMs = fact.OccurredAtUnixMs });
                else if (fact.OccurredAtUnixMs < first.FirstSeenAtUnixMs)
                    first.FirstSeenAtUnixMs = fact.OccurredAtUnixMs;
            }
            var threat = await threats.ApplyAsync(db, interactionEvent, cancellationToken);
            await evidenceStore.ConfirmPasswordBookAttemptAsync(db, interactionEvent, cancellationToken, receivedAt);
            await db.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);

            // 提交后状态可直接从数据库读取。外发失败不改变数据库写入结果。
            health.RecordPersisted(_time.GetUtcNow());
            health.SetDiskBudgetBlocked(false);
            if (_consecutiveFailures >= 3)
                SyslogInteractionProjection.PublishSafely(logs, "honeypot-events", "EVENT_PERSISTENCE_RECOVERED", SyslogSeverity.Notice,
                    new Dictionary<string, object?> { ["failureCount"] = _consecutiveFailures });
            _consecutiveFailures = 0;
            if (threat.Profile is { } profile && !string.Equals(threat.PreviousStatus, profile.Status, StringComparison.Ordinal))
                SyslogInteractionProjection.PublishSafely(logs, "honeypot-engine", "THREAT_STATUS_CHANGED",
                    profile.Status == "Suspicious" ? SyslogSeverity.Notice : SyslogSeverity.Informational,
                    new Dictionary<string, object?> { ["eventId"] = interactionEvent.EventId, ["sourceIp"] = profile.SourceIp,
                        ["previousState"] = threat.PreviousStatus, ["state"] = profile.Status, ["riskScore"] = profile.CurrentScore,
                        ["outcome"] = "observed" });
            return EventAppendResult.Accepted();
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception error) when (IsSqliteFull(error))
        {
            health.SetDiskBudgetBlocked(true);
            return Failed("REPORT_DISK_BUDGET_EXCEEDED", "报告数据库空间或可用磁盘空间已达限制。");
        }
        catch (Exception)
        {
            return Failed("REPORT_PERSISTENCE_FAILED", "报告事件持久化失败，未确认接收。");
        }

        EventAppendResult Failed(string code, string message)
        {
            health.RecordRejectedEvent();
            // 不输出异常正文/参数，以免驱动附带不可信事件字段。
            _consecutiveFailures++;
            if (_consecutiveFailures == 1 || _consecutiveFailures == 3)
                logger.LogError("Report event persistence failed. ErrorCode={ErrorCode} FailureCount={FailureCount}", code, health.PersistenceFailures);
            if (_consecutiveFailures == 3)
                SyslogInteractionProjection.PublishSafely(logs, "honeypot-events", "EVENT_PERSISTENCE_UNAVAILABLE", SyslogSeverity.Critical,
                    new Dictionary<string, object?> { ["failureCount"] = _consecutiveFailures, ["errorCode"] = code });
            return EventAppendResult.DegradedResult(code, message);
        }
    }

    private static bool IsSqliteFull(Exception error) =>
        (error is DbUpdateException ? error.InnerException : error) is SqliteException { SqliteErrorCode: 13 };

    public ValueTask<string> StoreAsync(CredentialEvidence evidence, CancellationToken cancellationToken = default) =>
        StoreEvidenceAsync(evidenceStore, evidence, cancellationToken);

    internal static async ValueTask<string> StoreEvidenceAsync(ICredentialEvidenceStore store, CredentialEvidence evidence,
        CancellationToken cancellationToken)
    {
        var content = evidence.ContentEncoding == "utf8-json" || string.Equals(evidence.MaterialType, "Plaintext", StringComparison.OrdinalIgnoreCase)
            ? Encoding.UTF8.GetString(evidence.Content.Span)
            : $"base64:{Convert.ToBase64String(evidence.Content.Span)}";
        var summary = await store.SaveAsync(evidence.ConnectionId, evidence.EventId, evidence.SourceIp, evidence.AdapterKey,
            evidence.MaterialType, content, evidence.RetentionDays, cancellationToken);
        return summary.CredentialArtifactId;
    }

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

    private sealed record PendingEvent(InteractionEvent Event, CancellationToken CancellationToken)
    {
        public TaskCompletionSource<EventAppendResult> Completion { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    }
}
