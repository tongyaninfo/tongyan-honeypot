using System.Collections.Concurrent;
using Honeypot.Protocol.Abstractions.Models;
using Honeypot.Protocol.Abstractions.Service;

namespace Honeypot.Runtime.Service;

/// <summary>
/// 本地开发和协议回放使用的内存事件接收器。正式环境应替换为可靠队列/WAL 实现。
/// </summary>
public sealed class InMemoryInteractionEventSink : IInteractionEventSink
{
    private readonly ConcurrentDictionary<string, InteractionEvent> _events = new(StringComparer.Ordinal);

    public IReadOnlyCollection<InteractionEvent> Events => _events.Values.ToArray();

    public ValueTask<EventAppendResult> AppendAsync(
        InteractionEvent interactionEvent,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!_events.TryAdd(interactionEvent.EventId, interactionEvent))
        {
            return ValueTask.FromResult(EventAppendResult.DegradedResult(
                "DUPLICATE_EVENT",
                $"Event '{interactionEvent.EventId}' has already been recorded."));
        }

        return ValueTask.FromResult(EventAppendResult.Accepted());
    }
}
