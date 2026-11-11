using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using Honeypot.Protocol.Abstractions.Models;
using Honeypot.Protocol.Abstractions.Service;
using Honeypot.Protocols.Common;
using Honeypot.Protocols.Db2;
using Honeypot.Protocols.Oracle;
using Honeypot.Protocols.HBase;

// 仅绑定随机回环端口。客户端参数中的 {port} 替换为本次端口，不连接真实数据库。
if (args.Length < 3) throw new ArgumentException("Usage: <db2|oracle|hbase> <client executable> <client arguments with {port}>");
IHoneypotServiceAdapter adapter = args[0] switch
{ "db2" => new Db2Adapter(), "oracle" => new OracleAdapter(), "hbase" => new HBaseAdapter(), _ => throw new ArgumentException("Unknown adapter") };
using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(45));
var sink = new ProbeSink();
var errors = new ConcurrentQueue<Exception>();
var listener = new TcpListener(IPAddress.Loopback, 0);
listener.Start();
var port = ((IPEndPoint)listener.LocalEndpoint).Port;
var accept = Task.Run(async () =>
{
    using var client = await listener.AcceptTcpClientAsync(stop.Token);
    await using var session = new ProbeSession(client);
    var profile = new ServiceProfile { ProfileId = "isolated-probe", AdapterKey = args[0], HandshakeTimeout = TimeSpan.FromSeconds(15) };
    try
    {
        await adapter.HandleAsync(session, new ProtocolSessionContext("isolated-connection", "isolated-listener", "isolated-instance",
            profile.AdapterKey, profile.ProfileId, session.RemoteEndPoint, session.LocalEndPoint, DateTimeOffset.UtcNow), profile, sink, stop.Token);
    }
    catch (Exception ex) { errors.Enqueue(ex); }
}, stop.Token);
var start = new ProcessStartInfo(args[1]) { UseShellExecute = false };
foreach (var argument in args.Skip(2)) start.ArgumentList.Add(argument.Replace("{port}", port.ToString(), StringComparison.Ordinal));
try
{
    using var process = Process.Start(start) ?? throw new InvalidOperationException("Client did not start");
    try { await process.WaitForExitAsync(stop.Token); }
    finally { if (!process.HasExited) process.Kill(entireProcessTree: true); }
    if (process.ExitCode != 0) throw new InvalidOperationException($"Client failed with exit code {process.ExitCode}");
    await accept.WaitAsync(stop.Token);
    if (!errors.IsEmpty) throw new InvalidOperationException("Adapter raised an unexpected error");
    var authentication = sink.Events.Where(e => e.EventType == "AuthenticationAttempted").ToArray();
    if (authentication.Length != 1 || sink.Evidence.Count != 1) throw new InvalidOperationException("Expected one authentication and one evidence artifact");
    var evidence = sink.Evidence.Single();
    using var json = JsonDocument.Parse(evidence.Content);
    if (authentication[0].Username != "isolated_user" || evidence.EventId != authentication[0].EventId)
        throw new InvalidOperationException("Identity/evidence association failed");
    var password = json.RootElement.GetProperty("password");
    if (args[0] == "db2" ? password.GetString() != "isolated-test-secret" : password.ValueKind != JsonValueKind.Null)
        throw new InvalidOperationException("Incorrect credential classification/content");
    if (JsonSerializer.Serialize(sink.Events).Contains("isolated-test-secret", StringComparison.Ordinal))
        throw new InvalidOperationException("Credential leaked into ordinary events");
    Console.WriteLine($"PASS {args[0]}: native authentication failure; one correlated {evidence.MaterialType} artifact; ordinary events contain no password.");
}
finally { await stop.CancelAsync(); listener.Stop(); }

sealed class ProbeSession(TcpClient client) : IHoneypotSession
{
    private readonly NetworkStream _stream = client.GetStream();
    public string ConnectionId => "isolated-connection";
    public EndPoint RemoteEndPoint => client.Client.RemoteEndPoint!;
    public EndPoint LocalEndPoint => client.Client.LocalEndPoint!;
    public string Transport => "tcp";
    public bool IsClosed { get; private set; }
    public ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct) => _stream.ReadAsync(buffer, ct);
    public ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct) => _stream.WriteAsync(buffer, ct);
    public ValueTask CloseAsync(SessionCloseReason reason, CancellationToken ct = default) { IsClosed = true; client.Dispose(); return ValueTask.CompletedTask; }
    public ValueTask DisposeAsync() { client.Dispose(); return ValueTask.CompletedTask; }
}
sealed class ProbeSink : IInteractionEventSink, ICredentialEvidenceSink
{
    public ConcurrentQueue<InteractionEvent> Events { get; } = [];
    public ConcurrentQueue<CredentialEvidence> Evidence { get; } = [];
    public ValueTask<EventAppendResult> AppendAsync(InteractionEvent value, CancellationToken ct = default)
    { Events.Enqueue(value); return ValueTask.FromResult(EventAppendResult.Accepted()); }
    public ValueTask<string> StoreAsync(CredentialEvidence value, CancellationToken ct = default)
    { Evidence.Enqueue(value with { Content = value.Content.ToArray() }); return ValueTask.FromResult("isolated-artifact"); }
}
