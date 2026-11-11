using System.Collections.Concurrent;
using System.Text;
using Honeypot.Engine.Service;
using Honeypot.Protocol.Abstractions.Models;
using Honeypot.Protocol.Abstractions.Service;
using Honeypot.Protocols.Common;
using Honeypot.Api.Common;
using Honeypot.Shared.Models;

namespace Honeypot.Api.Service.impl;

/// <summary>
/// 初始化阶段的事件接收器：先去重、入队，再同步更新威胁聚合，保证查询立即可见。
/// </summary>
public sealed class InMemoryInteractionEventStore : IInteractionEventStore, ICredentialEvidenceSink
{
    private readonly ConcurrentDictionary<string, InteractionEvent> _events = new(StringComparer.OrdinalIgnoreCase);
    private readonly IThreatProfileStore _threatProfileStore;
    private readonly ICredentialEvidenceStore _credentialEvidenceStore;
    private readonly ISyslogPublisher? _syslog;
    private readonly object _appendGate = new();

    public InMemoryInteractionEventStore(
        IThreatProfileStore threatProfileStore,
        ICredentialEvidenceStore credentialEvidenceStore,
        ISyslogPublisher? syslog = null)
    {
        _threatProfileStore = threatProfileStore;
        _credentialEvidenceStore = credentialEvidenceStore;
        _syslog = syslog;
    }

    public async ValueTask<string> StoreAsync(
        CredentialEvidence evidence,
        CancellationToken cancellationToken = default)
    {
        var content = evidence.ContentEncoding == "utf8-json" || string.Equals(evidence.MaterialType, "Plaintext", StringComparison.OrdinalIgnoreCase)
            ? Encoding.UTF8.GetString(evidence.Content.Span)
            : $"base64:{Convert.ToBase64String(evidence.Content.Span)}";
        var summary = await _credentialEvidenceStore.SaveAsync(
            evidence.ConnectionId,
            evidence.EventId,
            evidence.SourceIp,
            evidence.AdapterKey,
            evidence.MaterialType,
            content,
            evidence.RetentionDays,
            cancellationToken);
        return summary.CredentialArtifactId;
    }

    public ValueTask<EventAppendResult> AppendAsync(
        InteractionEvent interactionEvent,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        // 旧适配器或扩展错误赋值时也不能把密码留在普通事件集合中。
        interactionEvent = interactionEvent with { Password = null };
        string? previousStatus;
        string status;
        int score;
        lock (_appendGate)
        {
            if (!_events.TryAdd(interactionEvent.EventId, interactionEvent))
                return ValueTask.FromResult(EventAppendResult.Duplicate());
            // 在宿主边界观察状态变化，保持 Engine 无日志传输依赖；与去重共用锁避免并发重复状态事件。
            previousStatus = _threatProfileStore.GetByIp(interactionEvent.SourceIp)?.Status;
            try
            {
                var profile = _threatProfileStore.Apply(interactionEvent);
                status = profile.Status;
                score = profile.CurrentScore;
            }
            catch (Exception)
            {
                SyslogInteractionProjection.PublishSafely(_syslog, "honeypot-engine", "THREAT_AGGREGATION_FAILED", SyslogSeverity.Error,
                    new Dictionary<string, object?> { ["eventId"] = interactionEvent.EventId, ["errorCode"] = "THREAT_AGGREGATION_FAILED" });
                throw;
            }
        }
        if (!string.Equals(previousStatus, status, StringComparison.Ordinal))
            SyslogInteractionProjection.PublishSafely(_syslog, "honeypot-engine", "THREAT_STATUS_CHANGED",
                status == "Suspicious" ? SyslogSeverity.Notice : SyslogSeverity.Informational,
                new Dictionary<string, object?> { ["eventId"] = interactionEvent.EventId, ["sourceIp"] = interactionEvent.SourceIp,
                    ["previousState"] = previousStatus, ["state"] = status, ["riskScore"] = score, ["outcome"] = "observed" });
        return ValueTask.FromResult(EventAppendResult.Accepted());
    }

    public IReadOnlyCollection<InteractionEvent> GetAll() => _events.Values
        .OrderByDescending(item => item.OccurredAtUtc)
        .ThenByDescending(item => item.Sequence)
        .ToArray();

    public IReadOnlyCollection<InteractionEvent> GetByConnectionId(string connectionId) => _events.Values
        .Where(item => item.ConnectionId.Equals(connectionId, StringComparison.OrdinalIgnoreCase))
        .OrderBy(item => item.Sequence)
        .ThenBy(item => item.OccurredAtUtc)
        .ToArray();
}
