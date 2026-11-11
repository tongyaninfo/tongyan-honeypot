namespace Honeypot.Protocol.Abstractions.Models;

public sealed record ListenerRuntimeStatus(
    string ListenerId,
    string InstanceId,
    string BindAddress,
    int Port,
    string Transport,
    string State,
    int ActiveConnections,
    long AcceptedCount,
    long ErrorCount,
    string? LastError);

public sealed record ListenerApplyResult(bool Succeeded, string Code, string Message)
{
    public static ListenerApplyResult Applied(string message = "listeners applied") =>
        new(true, "APPLIED", message);

    public static ListenerApplyResult Failed(string code, string message) =>
        new(false, code, message);
}
