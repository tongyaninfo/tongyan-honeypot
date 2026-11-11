namespace Honeypot.Protocol.Abstractions.Service;

public interface IConnectionIdGenerator
{
    string NewConnectionId();
    string NewEventId();
}
