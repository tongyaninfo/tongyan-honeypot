using Honeypot.Protocol.Abstractions.Models;

namespace Honeypot.Protocol.Abstractions.Service;

public interface IInteractionEventSink
{
    ValueTask<EventAppendResult> AppendAsync(
        InteractionEvent interactionEvent,
        CancellationToken cancellationToken = default);
}
