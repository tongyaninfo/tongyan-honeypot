using Honeypot.Protocol.Abstractions.Models;
using Honeypot.Protocol.Abstractions.Service;

namespace Honeypot.Api.Service;

public interface IInteractionEventStore : IInteractionEventSink
{
    IReadOnlyCollection<InteractionEvent> GetAll();

    IReadOnlyCollection<InteractionEvent> GetByConnectionId(string connectionId);
}
