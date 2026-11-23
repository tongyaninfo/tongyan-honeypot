using Honeypot.Protocol.Abstractions.Models;
using Honeypot.Protocol.Abstractions.Service;
using Honeypot.Protocols.Common;
using Honeypot.Api.Common;

namespace Honeypot.Api.Service.impl;

/// <summary>
/// 在既有事件存储旁路广播事件，保留认证证据接口转发能力。
/// </summary>
public sealed class RealtimeInteractionEventSink : IInteractionEventSink, ICredentialEvidenceSink, ICredentialEventSink
{
    private readonly IInteractionEventStore _inner;
    private readonly ICredentialEvidenceSink _credentialSink;
    private readonly IRealtimeUpdateNotifier _notifier;
    private readonly ILogger<RealtimeInteractionEventSink> _logger;
    private readonly ISyslogPublisher? _syslog;

    public RealtimeInteractionEventSink(
        IInteractionEventStore inner,
        ICredentialEvidenceSink credentialSink,
        IRealtimeUpdateNotifier notifier,
        ILogger<RealtimeInteractionEventSink> logger,
        ISyslogPublisher? syslog = null)
    {
        _inner = inner;
        _credentialSink = credentialSink;
        _notifier = notifier;
        _logger = logger;
        _syslog = syslog;
    }

    public async ValueTask<EventAppendResult> AppendAsync(
        InteractionEvent interactionEvent,
        CancellationToken cancellationToken = default)
    {
        interactionEvent = InteractionEventSanitizer.Sanitize(interactionEvent);
        var result = await _inner.AppendAsync(interactionEvent, cancellationToken);
        await NotifyCommittedAsync(interactionEvent, result, cancellationToken);
        return result;
    }

    public async ValueTask<CredentialEventResult> AppendWithEvidenceAsync(InteractionEvent item, CredentialEvidence evidence, CancellationToken cancellationToken = default)
    {
        var saved = await CredentialEventRecording.AppendAsync(_inner, InteractionEventSanitizer.Sanitize(item), evidence, cancellationToken);
        await NotifyCommittedAsync(saved.Event, saved.Result, cancellationToken);
        return saved;
    }

    private async Task NotifyCommittedAsync(InteractionEvent interactionEvent, EventAppendResult result, CancellationToken cancellationToken)
    {
        if (!result.Recorded || result.IsDuplicate) return;

        SyslogInteractionProjection.PublishSafely(_syslog, SyslogInteractionProjection.AppName(interactionEvent.AdapterKey),
            interactionEvent.EventType, SyslogInteractionProjection.Severity(interactionEvent),
            SyslogInteractionProjection.Fields(interactionEvent));

        try
        {
            await _notifier.PublishEventAsync(interactionEvent, cancellationToken);
        }
        catch (Exception exception)
        {
            // 事件已经成功记录，SignalR 故障不应改变记录结果。
            _logger.LogError("Realtime event broadcast failed for {EventId}: {ErrorCode}", interactionEvent.EventId, exception.GetType().Name);
        }

    }

    public ValueTask<string> StoreAsync(
        CredentialEvidence evidence,
        CancellationToken cancellationToken = default) =>
        _credentialSink.StoreAsync(evidence, cancellationToken);
}
