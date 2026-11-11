using System.Net;

namespace Honeypot.Protocol.Abstractions.Models;

public sealed record ProtocolSessionContext(
    string ConnectionId,
    string ListenerId,
    string ServiceInstanceId,
    string AdapterKey,
    string ProfileId,
    EndPoint RemoteEndPoint,
    EndPoint LocalEndPoint,
    DateTimeOffset AcceptedAtUtc);
