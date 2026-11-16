using Honeypot.Engine.Service;
using Honeypot.Protocol.Abstractions.Models;
using Honeypot.Protocol.Abstractions.Service;
using Honeypot.Protocols.Common;
using Honeypot.Api.Common;
using Honeypot.Api.Options;
using Honeypot.Shared.Models;
using Microsoft.Extensions.Options;

namespace Honeypot.Api.Service.impl;

/// <summary>
/// 初始化阶段的事件接收器：先去重、入队，再同步更新威胁聚合，保证查询立即可见。
/// </summary>
public sealed class InMemoryInteractionEventStore : IInteractionEventStore, ICredentialEvidenceSink
{
    private readonly Dictionary<string, InteractionEvent> _events = new(StringComparer.OrdinalIgnoreCase);
    private readonly Queue<(string EventId, long AddedTimestamp)> _order = new();
    private readonly IThreatProfileStore _threatProfileStore;
    private readonly ICredentialEvidenceStore _credentialEvidenceStore;
    private readonly ISyslogPublisher? _syslog;
    private readonly object _appendGate = new();
    private readonly TimeProvider _clock;
    private readonly int _capacity;
    private readonly TimeSpan _retention;

    public InMemoryInteractionEventStore(
        IThreatProfileStore threatProfileStore,
        ICredentialEvidenceStore credentialEvidenceStore,
        ISyslogPublisher? syslog = null,
        IOptions<EventStorageOptions>? options = null,
        TimeProvider? time = null)
    {
        _threatProfileStore = threatProfileStore;
        _credentialEvidenceStore = credentialEvidenceStore;
        _syslog = syslog;
        var settings = options?.Value ?? new EventStorageOptions();
        _capacity = settings.MemoryEventCapacity;
        _retention = TimeSpan.FromHours(settings.MemoryRetentionHours);
        _clock = time ?? TimeProvider.System;
    }

    public ValueTask<string> StoreAsync(
        CredentialEvidence evidence,
        CancellationToken cancellationToken = default) =>
        ReportInteractionEventStore.StoreEvidenceAsync(_credentialEvidenceStore, evidence, cancellationToken);

    public ValueTask<EventAppendResult> AppendAsync(
        InteractionEvent interactionEvent,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (string.IsNullOrWhiteSpace(interactionEvent.EventId) || interactionEvent.EventId.Length > 128 ||
            interactionEvent.EventId.Any(char.IsControl))
            return ValueTask.FromResult(EventAppendResult.DegradedResult("EVENT_INVALID_ID", "事件标识不符合记录约定。"));
        return AppendSanitizedAsync(InteractionEventSanitizer.Sanitize(interactionEvent));
    }

    internal ValueTask<EventAppendResult> AppendSanitizedAsync(InteractionEvent interactionEvent)
    {
        string? previousStatus;
        string status;
        int score;
        lock (_appendGate)
        {
            var now = _clock.GetTimestamp();
            Evict(now);
            if (_events.ContainsKey(interactionEvent.EventId))
                return ValueTask.FromResult(EventAppendResult.Duplicate());
            // 在宿主边界观察状态变化，保持 Engine 无日志传输依赖；与去重共用锁避免并发重复状态事件。
            try
            {
                var profile = _threatProfileStore.Apply(interactionEvent, out previousStatus);
                status = profile.Status;
                score = profile.CurrentScore;
            }
            catch (Exception)
            {
                SyslogInteractionProjection.PublishSafely(_syslog, "honeypot-engine", "THREAT_AGGREGATION_FAILED", SyslogSeverity.Error,
                    new Dictionary<string, object?> { ["eventId"] = interactionEvent.EventId, ["errorCode"] = "THREAT_AGGREGATION_FAILED" });
                throw;
            }
            while (_events.Count >= _capacity && _order.TryDequeue(out var oldest))
                _events.Remove(oldest.EventId);
            _events.Add(interactionEvent.EventId, interactionEvent);
            _order.Enqueue((interactionEvent.EventId, now));
            _credentialEvidenceStore.ConfirmPasswordBookAttempt(interactionEvent);
        }
        if (!string.Equals(previousStatus, status, StringComparison.Ordinal))
            SyslogInteractionProjection.PublishSafely(_syslog, "honeypot-engine", "THREAT_STATUS_CHANGED",
                status == "Suspicious" ? SyslogSeverity.Notice : SyslogSeverity.Informational,
                new Dictionary<string, object?> { ["eventId"] = interactionEvent.EventId, ["sourceIp"] = interactionEvent.SourceIp,
                    ["previousState"] = previousStatus, ["state"] = status, ["riskScore"] = score, ["outcome"] = "observed" });
        return ValueTask.FromResult(EventAppendResult.Accepted());
    }

    public IReadOnlyCollection<InteractionEvent> GetAll() => Snapshot()
        .OrderByDescending(item => item.OccurredAtUtc)
        .ThenByDescending(item => item.Sequence)
        .ToArray();

    public IReadOnlyCollection<InteractionEvent> GetByConnectionId(string connectionId) => Snapshot(connectionId)
        .OrderBy(item => item.Sequence)
        .ThenBy(item => item.OccurredAtUtc)
        .ToArray();

    private InteractionEvent[] Snapshot(string? connectionId = null)
    {
        lock (_appendGate)
        {
            Evict(_clock.GetTimestamp());
            return connectionId is null ? _events.Values.ToArray() : _events.Values
                .Where(item => item.ConnectionId.Equals(connectionId, StringComparison.OrdinalIgnoreCase)).ToArray();
        }
    }

    private void Evict(long now)
    {
        // 用单调时钟计算入库后的留存时间，避免来源时间和系统时钟回拨影响淘汰。
        while (_order.TryPeek(out var oldest) && _clock.GetElapsedTime(oldest.AddedTimestamp, now) >= _retention)
        {
            _order.Dequeue();
            _events.Remove(oldest.EventId);
        }
    }
}
