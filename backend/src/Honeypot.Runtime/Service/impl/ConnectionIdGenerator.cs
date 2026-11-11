using Honeypot.Protocol.Abstractions.Service;

namespace Honeypot.Runtime.Service.impl;

public sealed class ConnectionIdGenerator : IConnectionIdGenerator
{
    public string NewConnectionId() => $"conn-{Guid.NewGuid():N}";

    public string NewEventId() => $"evt-{Guid.NewGuid():N}";
}
