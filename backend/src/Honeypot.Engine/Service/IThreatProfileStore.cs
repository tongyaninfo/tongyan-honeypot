using Honeypot.Engine.Models;
using Honeypot.Protocol.Abstractions.Models;

namespace Honeypot.Engine.Service;

public interface IThreatProfileStore
{
    ThreatIpProfile Apply(InteractionEvent interactionEvent);

    IReadOnlyCollection<ThreatIpProfile> GetAll();

    ThreatIpProfile? GetByIp(string sourceIp);
}
