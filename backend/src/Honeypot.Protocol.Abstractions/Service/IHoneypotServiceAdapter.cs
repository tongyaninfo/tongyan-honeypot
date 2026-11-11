using Honeypot.Protocol.Abstractions.Models;

namespace Honeypot.Protocol.Abstractions.Service;

public interface IHoneypotServiceAdapter
{
    ServiceAdapterDescriptor Descriptor { get; }

    ValueTask<AdapterValidationResult> ValidateAsync(
        ServiceProfile profile,
        CancellationToken cancellationToken = default);

    ValueTask HandleAsync(
        IHoneypotSession session,
        ProtocolSessionContext context,
        ServiceProfile profile,
        IInteractionEventSink eventSink,
        CancellationToken cancellationToken = default);
}
