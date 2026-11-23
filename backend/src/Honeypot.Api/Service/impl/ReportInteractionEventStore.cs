using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using Honeypot.Engine.Models;
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
    ReportEventDiskBudget? diskBudget = null) : IInteractionEventStore, ICredentialEvidenceSink, ICredentialEventSink
{
    private readonly EventStorageOptions _options = options?.Value ?? new();
    private readonly TimeProvider _time = time ?? TimeProvider.System;
    private readonly ReportEventDiskBudget _diskBudget = diskBudget ?? new();
    private readonly Channel<PendingEvent> _queue = Channel.CreateBounded<PendingEvent>(
        new BoundedChannelOptions((options?.Value ?? new EventStorageOptions()).QueueCapacity) { SingleReader = true });
    private int _consecutiveFailures;

    public async ValueTask<EventAppendResult> AppendAsync(InteractionEvent interactionEvent, CancellationToken cancellationToken = default) =>
        (await EnqueueAsync(interactionEvent, null, cancellationToken)).Result;

    public async ValueTask<CredentialEventResult> AppendWithEvidenceAsync(InteractionEvent item, CredentialEvidence evidence,
        CancellationToken cancellationToken = default)
    {
        if (item.EventId != evidence.EventId || item.ConnectionId != evidence.ConnectionId || item.AdapterKey != evidence.AdapterKey ||
            item.SourceIp != evidence.SourceIp || item.MaterialType != evidence.MaterialType)
            throw new AuthenticationRecordingException("CredentialCaptureFailed");
        if (evidenceStore is not SqliteCredentialEvidenceStore sqlite)
        {
            var saved = await StoreEvidenceAsync(evidenceStore, evidence, cancellationToken);
            return await EnqueueAsync(item with { CredentialArtifactId = saved, CredentialCaptureStatus = "Captured" }, null, cancellationToken);
        }

        CredentialEvidenceEntity row;
        try
        {
            row = await sqlite.PrepareAsync(evidence.ConnectionId, evidence.EventId, evidence.SourceIp, evidence.AdapterKey,
                evidence.MaterialType, Content(evidence), evidence.RetentionDays, cancellationToken, item);
            health.RecoverStage("evidence.prepare");
        }
        catch (Exception error) when (error is not OperationCanceledException)
        {
            var code = error is CryptographicException ? "EVIDENCE_KEY_UNAVAILABLE" : ReportIngestionHealth.Classify(error);
            health.RecordStageFault("evidence.prepare", code);
            throw;
        }
        return await EnqueueAsync(item with { CredentialArtifactId = row.ArtifactId, CredentialCaptureStatus = "Captured" }, row, cancellationToken);
    }

    private async ValueTask<CredentialEventResult> EnqueueAsync(InteractionEvent item, CredentialEvidenceEntity? evidence, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        if (string.IsNullOrWhiteSpace(item.EventId) || item.EventId.Length > 128 || item.EventId.Any(char.IsControl))
        {
            health.RecordRejectedEvent("REPORT_INVALID_EVENT_ID", "event.enqueue");
            return new(item, EventAppendResult.DegradedResult("REPORT_INVALID_EVENT_ID", "事件标识不符合持久化约定。"));
        }
        var pending = new PendingEvent(InteractionEventSanitizer.Sanitize(item), evidence);
        // 等待者是已受运行时准入限制的监听或会话任务；队列满时其生产方自然停读。
        health.ChangeQueueDepth(1);
        try
        {
            await _queue.Writer.WriteAsync(pending, ct);
            health.RecoverStage("event.enqueue");
        }
        catch (Exception error) when (error is OperationCanceledException or ChannelClosedException)
        {
            health.ChangeQueueDepth(-1);
            var code = error is ChannelClosedException ? "REPORT_EVENT_WRITER_STOPPED" : "REPORT_QUEUE_WAIT_CANCELLED";
            health.RecordRejectedEvent(code, "event.enqueue");
            if (error is OperationCanceledException) throw;
            return new(item, EventAppendResult.DegradedResult(code, "事件写入已停止。"));
        }
        // 接受入队后的写入由宿主持有；调用方超时、重放均不得撤回已接收工作。
        return await pending.Completion.Task.WaitAsync(ct);
    }

    internal void CompleteQueue() => _queue.Writer.TryComplete();

    internal async Task WriteQueuedEventsAsync(CancellationToken stoppingToken)
    {
        try
        {
            while (await _queue.Reader.WaitToReadAsync(stoppingToken))
            {
                var batch = new List<PendingEvent>(16);
                while (batch.Count < 16 && _queue.Reader.TryRead(out var pending))
                {
                    health.ChangeQueueDepth(-1);
                    ReportIngestionHealth.RecordQueue(pending.Start);
                    batch.Add(pending);
                }
                await WriteBatchAsync(batch, stoppingToken);
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
        finally
        {
            CompleteQueue();
            while (_queue.Reader.TryRead(out var remaining))
            {
                health.ChangeQueueDepth(-1);
                Fail(remaining, "REPORT_EVENT_WRITER_STOPPED");
            }
        }
    }

    private async Task WriteBatchAsync(List<PendingEvent> batch, CancellationToken ct)
    {
        if (batch.Count == 0) return;
        for (var attempt = 0; ; attempt++)
        {
            try
            {
                await CommitBatchAsync(batch, ct);
                return;
            }
            catch (Exception error) when (!ct.IsCancellationRequested && attempt == 0 && ReportIngestionHealth.Classify(error) == "SQLITE_BUSY")
            {
                // 驱动已执行一次最长 1 秒的锁等待；只允许再试一次，幂等查询在新事务内重新执行。
                health.RecordLockRetry();
            }
            catch (Exception error)
            {
                var code = ct.IsCancellationRequested ? "REPORT_EVENT_WRITER_STOPPED" : ReportIngestionHealth.Classify(error);
                if (batch.Count > 1 && !ct.IsCancellationRequested && (code == "REPORT_PERSISTENCE_FAILED" ||
                    error is CryptographicException || code == "SQLITE_FULL" && batch.Any(pending => pending.Evidence is not null)))
                {
                    // 大证据写满后，小型接纳/关闭仍可能写入。分项重试，只按最终失败项计算故障。
                    foreach (var pending in batch) await WriteBatchAsync([pending], ct);
                }
                else
                {
                    foreach (var pending in batch)
                    {
                        if (error is CryptographicException && pending.Evidence is not null)
                        {
                            health.RecordRejectedEvent("CREDENTIAL_CAPTURE_FAILED", "evidence.commit");
                            pending.Completion.TrySetException(new AuthenticationRecordingException("CredentialCaptureFailed"));
                        }
                        else Fail(pending, code);
                    }
                }
                return;
            }
        }
    }

    private async Task CommitBatchAsync(List<PendingEvent> batch, CancellationToken ct)
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        db.Database.SetCommandTimeout(1);
        if (db.Database.GetDbConnection() is SqliteConnection sqlite) sqlite.DefaultTimeout = 1;
        await db.Database.OpenConnectionAsync(ct);
        await using var transaction = await AcquireWriteLockAsync(db, ct);
        var results = new List<(CredentialEventResult Saved, ThreatIpProfile? Profile, string? Previous)>(batch.Count);
        foreach (var pending in batch) results.Add(await ApplyAsync(db, pending, ct));
        var commitStart = Stopwatch.GetTimestamp();
        await transaction.CommitAsync(ct);
        ReportIngestionHealth.RecordCommit(commitStart);
        _diskBudget.Observe(db, health);
        health.SetDiskBudgetBlocked(false);
        if (_consecutiveFailures >= 3)
            SyslogInteractionProjection.PublishSafely(logs, "honeypot-events", "EVENT_PERSISTENCE_RECOVERED", SyslogSeverity.Notice,
                new Dictionary<string, object?> { ["failureCount"] = _consecutiveFailures });
        _consecutiveFailures = 0;

        for (var i = 0; i < batch.Count; i++)
        {
            var (saved, profile, previous) = results[i];
            health.RecoverStage(batch[i].Evidence is null ? "event.commit" : "evidence.commit");
            if (!saved.Result.IsDuplicate)
            {
                health.RecordPersisted(_time.GetUtcNow());
                if (batch[i].Evidence is { } evidence && evidenceStore is SqliteCredentialEvidenceStore credentials)
                    credentials.PublishCaptured(evidence);
                if (profile is not null && profile.Status != previous)
                    SyslogInteractionProjection.PublishSafely(logs, "honeypot-engine", "THREAT_STATUS_CHANGED",
                        profile.Status == "Suspicious" ? SyslogSeverity.Notice : SyslogSeverity.Informational,
                        new Dictionary<string, object?> { ["eventId"] = saved.Event.EventId, ["sourceIp"] = profile.SourceIp,
                            ["previousState"] = previous, ["state"] = profile.Status, ["riskScore"] = profile.CurrentScore, ["outcome"] = "observed" });
            }
            ReportIngestionHealth.RecordAppend(batch[i].Start);
            batch[i].Completion.TrySetResult(saved);
        }
    }

    private static async Task<Microsoft.EntityFrameworkCore.Storage.IDbContextTransaction> AcquireWriteLockAsync(HoneypotDbContext db, CancellationToken ct)
    {
        var start = Stopwatch.GetTimestamp();
        try { return await db.Database.BeginTransactionAsync(ct); }
        finally { ReportIngestionHealth.RecordWriteLock(start); }
    }

    private async Task<(CredentialEventResult Saved, ThreatIpProfile? Profile, string? Previous)> ApplyAsync(
        HoneypotDbContext db, PendingEvent pending, CancellationToken cancellationToken)
    {
        var interactionEvent = pending.Event;
        var fact = Project(interactionEvent);
        var existing = await db.Set<ReportEventEntity>().AsNoTracking().Where(e => e.EventId == fact.EventId)
            .Select(e => new { e.CredentialArtifactId }).SingleOrDefaultAsync(cancellationToken);
        if (existing is not null || await db.Set<InteractionEventEntity>().AnyAsync(e => e.EventId == fact.EventId, cancellationToken))
        {
            if (pending.Evidence is not null)
            {
                // 调用者超时后的重放只返回原提交的引用，不会返回这次新准备的证据编号。
                var detail = await db.Set<InteractionEventEntity>().AsNoTracking().Where(e => e.EventId == fact.EventId)
                    .Select(e => e.EventJson).SingleOrDefaultAsync(cancellationToken);
                interactionEvent = detail is not null ? InteractionEventEntity.Read(detail) : interactionEvent with
                    { CredentialArtifactId = existing?.CredentialArtifactId, CredentialCaptureStatus = existing?.CredentialArtifactId is null ? "Unavailable" : "Captured" };
            }
            return (new(interactionEvent, EventAppendResult.Duplicate()), null, null);
        }
        var receivedAt = _time.GetUtcNow();
        db.Add(fact);
        db.Add(InteractionEventEntity.FromSanitized(interactionEvent, receivedAt, _options.HandshakeRetentionHours));
        await UpdateConnectionSummaryAsync(db, interactionEvent, receivedAt, cancellationToken);
        ThreatIpProfile? profile = null;
        string? previous = null;
        if (fact.SourceIp.Length > 0)
        {
            var first = await db.Set<ReportSourceFirstSeenEntity>().FindAsync([fact.SourceIp], cancellationToken);
            if (first is null) db.Add(new ReportSourceFirstSeenEntity { SourceIp = fact.SourceIp, FirstSeenAtUnixMs = fact.OccurredAtUnixMs });
            else if (fact.OccurredAtUnixMs < first.FirstSeenAtUnixMs) first.FirstSeenAtUnixMs = fact.OccurredAtUnixMs;
            (profile, previous) = await threats.ApplyAsync(db, interactionEvent, cancellationToken);
        }
        if (pending.Evidence is { } evidence)
        {
            await SqliteCredentialEvidenceStore.CheckKeyAsync(db, evidence.KeyId, cancellationToken);
            db.Add(evidence);
        }
        else await evidenceStore.ConfirmPasswordBookAttemptAsync(db, interactionEvent, cancellationToken, receivedAt);
        // 使本批下一项（同 IP、同连接或重放）能看到前序变更；确认仍等到整批提交。
        await db.SaveChangesAsync(cancellationToken);
        return (new(interactionEvent, EventAppendResult.Accepted()), profile, previous);
    }

    private void Fail(PendingEvent pending, string code)
    {
        health.RecordRejectedEvent(code, pending.Evidence is null ? "event.commit" : "evidence.commit");
        if (code == "SQLITE_FULL") health.SetDiskBudgetBlocked(true);
        _consecutiveFailures++;
        if (_consecutiveFailures == 1 || _consecutiveFailures == 3)
            logger.LogError("Report event persistence failed. Stage={Stage} ErrorCode={ErrorCode} Count={Count}",
                Safe(pending.Event.EventType, 64), code, health.PersistenceFailures);
        if (_consecutiveFailures == 3)
            SyslogInteractionProjection.PublishSafely(logs, "honeypot-events", "EVENT_PERSISTENCE_UNAVAILABLE", SyslogSeverity.Critical,
                new Dictionary<string, object?> { ["failureCount"] = _consecutiveFailures, ["errorCode"] = code });
        pending.Completion.TrySetResult(new(pending.Event with { CredentialArtifactId = null },
            EventAppendResult.DegradedResult(code, "事件写入失败，未确认接收。")));
    }

    public ValueTask<string> StoreAsync(CredentialEvidence evidence, CancellationToken cancellationToken = default) =>
        StoreEvidenceAsync(evidenceStore, evidence, cancellationToken);

    internal static async ValueTask<string> StoreEvidenceAsync(ICredentialEvidenceStore store, CredentialEvidence evidence,
        CancellationToken cancellationToken)
    {
        var content = Content(evidence);
        var summary = await store.SaveAsync(evidence.ConnectionId, evidence.EventId, evidence.SourceIp, evidence.AdapterKey,
            evidence.MaterialType, content, evidence.RetentionDays, cancellationToken);
        return summary.CredentialArtifactId;
    }

    private static string Content(CredentialEvidence evidence) =>
        evidence.ContentEncoding == "utf8-json" || string.Equals(evidence.MaterialType, "Plaintext", StringComparison.OrdinalIgnoreCase)
            ? Encoding.UTF8.GetString(evidence.Content.Span) : $"base64:{Convert.ToBase64String(evidence.Content.Span)}";

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
            Outcome = Safe(value.Outcome, 64).ToLowerInvariant() is { Length: > 0 } outcome ? outcome : "unknown",
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

    private sealed record PendingEvent(InteractionEvent Event, CredentialEvidenceEntity? Evidence)
    {
        public long Start { get; } = Stopwatch.GetTimestamp();
        public TaskCompletionSource<CredentialEventResult> Completion { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    }
}
