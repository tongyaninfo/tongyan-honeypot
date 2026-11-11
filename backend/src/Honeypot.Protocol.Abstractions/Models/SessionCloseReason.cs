namespace Honeypot.Protocol.Abstractions.Models;

public enum SessionCloseReason
{
    ClientClosed = 0,
    AdapterCompleted = 1,
    HandshakeTimeout = 2,
    IdleTimeout = 3,
    ResourceLimitExceeded = 4,
    ProtocolViolation = 5,
    StorageDegraded = 6,
    ListenerStopping = 7,
    InternalError = 8,
}
