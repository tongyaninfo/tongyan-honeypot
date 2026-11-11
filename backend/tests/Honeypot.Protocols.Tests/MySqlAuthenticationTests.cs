using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using Honeypot.Protocol.Abstractions.Models;
using Honeypot.Protocol.Abstractions.Service;
using Honeypot.Protocols.Common;
using Honeypot.Protocols.MySql;
using MySqlConnector;
using Xunit;

namespace Honeypot.Protocols.Tests;

public sealed class MySqlAuthenticationTests
{
    [Theory]
    [InlineData("caching_sha2_password", true, "隔离账号", "test-password-雪", "Plaintext")]
    [InlineData("caching_sha2_password", false, "user", "test-rsa-password", "Decrypted")]
    [InlineData("caching_sha2_password", false, "user", "", "Plaintext")]
    [InlineData("mysql_native_password", false, "user", "test-native-password", "Response")]
    [InlineData("mysql_native_password", true, "隔离账号", "test-native-tls", "Response")]
    public async Task RealDriverReceives1045AndRecordsActualCredential(string plugin, bool tls, string user, string password, string type)
    {
        var profile = AuthenticationTestServer.Profile("mysql") with { MySqlAuthenticationPlugin = plugin };
        await using var server = new AuthenticationTestServer(new MySqlAdapter(), profile);
        using var connection = new MySqlConnection(Connection(server.Port, tls, user, password));
        var error = await Assert.ThrowsAsync<MySqlException>(() => connection.OpenAsync());
        Assert.Equal(1045, error.Number);
        Assert.Equal("28000", error.SqlState);
        var authentication = await server.Sink.Authentication.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(user, authentication.Username);
        Assert.Equal("decoy", authentication.Database);
        Assert.Equal(plugin, authentication.AuthenticationMethod);
        Assert.Equal(type, authentication.MaterialType);
        Assert.Equal("Captured", authentication.CredentialCaptureStatus);
        var evidence = Assert.Single(server.Sink.Evidence);
        Assert.Equal(authentication.EventId, evidence.EventId);
        using var json = JsonDocument.Parse(evidence.Content);
        if (type != "Response") Assert.Equal(password, json.RootElement.GetProperty("password").GetString());
        else
        {
            Assert.Equal(JsonValueKind.Null, json.RootElement.GetProperty("password").ValueKind);
            Assert.Equal(20, Convert.FromBase64String(json.RootElement.GetProperty("authenticationResponse").GetString()!).Length);
        }
        Assert.Null(authentication.Password);
        if (password.Length > 0) Assert.DoesNotContain(password, JsonSerializer.Serialize(server.Sink.Events), StringComparison.Ordinal);
        Assert.Empty(server.Errors);
    }

    [Fact]
    public async Task DisabledCaptureDoesNotInventArtifactOrExposeUsername()
    {
        await using var server = new AuthenticationTestServer(new MySqlAdapter(), AuthenticationTestServer.Profile("mysql") with
        { RecordUsername = false, RecordPassword = false });
        using var connection = new MySqlConnection(Connection(server.Port, false, "user", "isolated-password"));
        Assert.Equal(1045, (await Assert.ThrowsAsync<MySqlException>(() => connection.OpenAsync())).Number);
        var authentication = await server.Sink.Authentication.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Null(authentication.Username);
        Assert.Null(authentication.CredentialArtifactId);
        Assert.Equal("Disabled", authentication.CredentialCaptureStatus);
        Assert.Empty(server.Sink.Evidence);
    }

    [Fact]
    public async Task StorageFailureStopsAuthenticationWithoutPretendingCaptureSucceeded()
    {
        await using var server = new AuthenticationTestServer(new MySqlAdapter(), AuthenticationTestServer.Profile("mysql"), failStorage: true);
        using var connection = new MySqlConnection(Connection(server.Port, false, "user", "isolated-password"));
        var error = await Assert.ThrowsAsync<MySqlException>(() => connection.OpenAsync());
        Assert.NotEqual(1045, error.Number);
        Assert.Contains(server.Sink.Events, x => x.EventType == "CredentialCaptureFailed");
        Assert.DoesNotContain(server.Sink.Events, x => x.EventType == "AuthenticationAttempted");
        Assert.Empty(server.Sink.Evidence);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task InvalidSequenceOrOversizeFrameCannotBecomeAuthentication(bool oversize)
    {
        var packet = oversize ? new byte[] { 0xff, 0xff, 0x7f, 1 } : new byte[] { 0, 0, 0, 9 };
        var session = new AuthenticationByteSession(packet, 1);
        var sink = new AuthenticationRecordingSink();
        await new MySqlAdapter().HandleAsync(session, AuthenticationTestServer.Context("mysql"), AuthenticationTestServer.Profile("mysql"), sink);
        Assert.Contains(sink.Events, x => x.EventType == "ProtocolViolation");
        Assert.DoesNotContain(sink.Events, x => x.EventType == "AuthenticationAttempted");
        Assert.Empty(sink.Evidence);
        Assert.True(session.IsClosed);
    }

    [Fact]
    public async Task UnsupportedConfiguredPluginFailsValidation()
    {
        var validation = await new MySqlAdapter().ValidateAsync(AuthenticationTestServer.Profile("mysql") with { MySqlAuthenticationPlugin = "unknown" });
        Assert.False(validation.IsValid);
    }

    [Fact]
    public async Task ClientDisconnectingBeforePublicKeyExchangeLeavesChallengeResponseEvidence()
    {
        await using var server = new AuthenticationTestServer(new MySqlAdapter(), AuthenticationTestServer.Profile("mysql"));
        using (var client = new TcpClient())
        {
            await client.ConnectAsync(IPAddress.Loopback, server.Port);
            var stream = client.GetStream();
            await ReadPacketAsync(stream);
            await stream.WriteAsync(CachingLoginPacket());
            Assert.Equal(new byte[] { 1, 4 }, await ReadPacketAsync(stream));
            // 客户端决定不进行公钥交换并断开，服务端仍保存已有响应。
        }
        var authentication = await server.Sink.Authentication.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal("partial-user", authentication.Username);
        Assert.Equal("Response", authentication.MaterialType);
        using var json = JsonDocument.Parse(Assert.Single(server.Sink.Evidence).Content);
        Assert.Equal(JsonValueKind.Null, json.RootElement.GetProperty("password").ValueKind);
        Assert.Equal(32, Convert.FromBase64String(json.RootElement.GetProperty("authenticationResponse").GetString()!).Length);
        Assert.Contains("before-full-auth", json.RootElement.GetProperty("stage").GetString(), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task InterruptedFullAuthenticationPreservesPreviouslyReceivedIdentity(bool timeout)
    {
        var session = new AuthenticationByteSession(CachingLoginPacket(), 1, waitWhenExhausted: timeout);
        var sink = new AuthenticationRecordingSink();
        await new MySqlAdapter().HandleAsync(session, AuthenticationTestServer.Context("mysql"),
            AuthenticationTestServer.Profile("mysql") with { HandshakeTimeout = TimeSpan.FromMilliseconds(100) }, sink);
        var authentication = Assert.Single(sink.Events, x => x.EventType == "AuthenticationAttempted");
        Assert.Equal("partial-user", authentication.Username);
        Assert.Equal("Response", authentication.MaterialType);
        using var json = JsonDocument.Parse(Assert.Single(sink.Evidence).Content);
        Assert.Equal(timeout ? "timeout-before-full-auth" : "client-closed-before-full-auth", json.RootElement.GetProperty("stage").GetString());
        Assert.Equal(JsonValueKind.Null, json.RootElement.GetProperty("password").ValueKind);
        Assert.True(session.IsClosed);
    }

    private static byte[] CachingLoginPacket()
    {
        using var payload = new MemoryStream(); using var writer = new BinaryWriter(payload);
        writer.Write(0x00088200u); writer.Write(65536u); writer.Write((byte)45); writer.Write(new byte[23]);
        writer.Write(Encoding.UTF8.GetBytes("partial-user\0")); writer.Write((byte)32); writer.Write(new byte[32]);
        writer.Write(Encoding.ASCII.GetBytes("caching_sha2_password\0"));
        var packet = new byte[payload.Length + 4]; packet[0] = (byte)payload.Length; packet[3] = 1; payload.ToArray().CopyTo(packet, 4);
        return packet;
    }

    private static async Task<byte[]> ReadPacketAsync(NetworkStream stream)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var header = new byte[4]; await stream.ReadExactlyAsync(header, timeout.Token);
        var payload = new byte[header[0] | (header[1] << 8) | (header[2] << 16)];
        await stream.ReadExactlyAsync(payload, timeout.Token); return payload;
    }

    private static string Connection(int port, bool tls, string username, string password) => new MySqlConnectionStringBuilder
    {
        Server = "127.0.0.1", Port = (uint)port, UserID = username, Password = password, Database = "decoy",
        SslMode = tls ? MySqlSslMode.Required : MySqlSslMode.None, AllowPublicKeyRetrieval = true,
        Pooling = false, ConnectionTimeout = 5,
    }.ConnectionString;
}

/// <summary>仅绑定临时回环端口，使用隔离凭据；不是数据库或系统服务。</summary>
internal sealed class AuthenticationTestServer : IAsyncDisposable
{
    private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource _stop = new();
    private readonly ConcurrentBag<Task> _sessions = [];
    private readonly Task _accept;
    public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;
    public AuthenticationRecordingSink Sink { get; }
    public ConcurrentBag<Exception> Errors { get; } = [];
    public AuthenticationTestServer(IHoneypotServiceAdapter adapter, ServiceProfile profile, bool failStorage = false)
    {
        Sink = new AuthenticationRecordingSink(failStorage);
        _listener.Start();
        _accept = AcceptAsync(adapter, profile);
    }
    public static ServiceProfile Profile(string protocol) => new()
    {
        ProfileId = "profile-auth-test", AdapterKey = protocol, HandshakeTimeout = TimeSpan.FromSeconds(5), IdleTimeout = TimeSpan.FromSeconds(5),
    };
    public static ProtocolSessionContext Context(string protocol) => new("conn-auth-test", "listener-auth-test", "instance-auth-test", protocol, "profile-auth-test",
        new IPEndPoint(IPAddress.Loopback, 50000), new IPEndPoint(IPAddress.Loopback, 3306), DateTimeOffset.UtcNow);
    private async Task AcceptAsync(IHoneypotServiceAdapter adapter, ServiceProfile profile)
    {
        try
        {
            while (!_stop.IsCancellationRequested)
            {
                var client = await _listener.AcceptTcpClientAsync(_stop.Token);
                _sessions.Add(HandleAsync(client, adapter, profile));
            }
        }
        catch (Exception ex) when (_stop.IsCancellationRequested && ex is OperationCanceledException or SocketException) { }
    }
    private async Task HandleAsync(TcpClient client, IHoneypotServiceAdapter adapter, ServiceProfile profile)
    {
        await using var session = new SocketSession(client);
        var context = new ProtocolSessionContext(session.ConnectionId, "listener-auth-test", "instance-auth-test", profile.AdapterKey,
            profile.ProfileId, session.RemoteEndPoint, session.LocalEndPoint, DateTimeOffset.UtcNow);
        try { await adapter.HandleAsync(session, context, profile, Sink, _stop.Token); }
        catch (Exception ex) when (_stop.IsCancellationRequested && ex is OperationCanceledException or IOException or ObjectDisposedException) { }
        catch (Exception ex) { Errors.Add(ex); }
    }
    public async ValueTask DisposeAsync()
    {
        await _stop.CancelAsync(); _listener.Stop();
        await _accept; await Task.WhenAll(_sessions.ToArray()).WaitAsync(TimeSpan.FromSeconds(10)); _stop.Dispose();
    }
    private sealed class SocketSession(TcpClient client) : IHoneypotSession, IRawStreamHoneypotSession
    {
        private readonly NetworkStream _stream = client.GetStream();
        public string ConnectionId { get; } = Guid.NewGuid().ToString("N");
        public EndPoint RemoteEndPoint { get; } = client.Client.RemoteEndPoint!;
        public EndPoint LocalEndPoint { get; } = client.Client.LocalEndPoint!;
        public string Transport => "tcp";
        public bool IsClosed { get; private set; }
        public Stream RawStream => _stream;
        public ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken) => _stream.ReadAsync(buffer, cancellationToken);
        public ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken) => _stream.WriteAsync(buffer, cancellationToken);
        public ValueTask CloseAsync(SessionCloseReason reason, CancellationToken cancellationToken = default) { IsClosed = true; client.Dispose(); return ValueTask.CompletedTask; }
        public ValueTask DisposeAsync() { client.Dispose(); return ValueTask.CompletedTask; }
    }
}

internal sealed class AuthenticationRecordingSink(bool failStorage = false) : IInteractionEventSink, ICredentialEvidenceSink
{
    public ConcurrentQueue<InteractionEvent> Events { get; } = [];
    public ConcurrentQueue<CredentialEvidence> Evidence { get; } = [];
    public TaskCompletionSource<InteractionEvent> Authentication { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    public ValueTask<EventAppendResult> AppendAsync(InteractionEvent interactionEvent, CancellationToken cancellationToken = default)
    {
        Events.Enqueue(interactionEvent);
        if (interactionEvent.EventType == "AuthenticationAttempted") Authentication.TrySetResult(interactionEvent);
        return ValueTask.FromResult(EventAppendResult.Accepted());
    }
    public ValueTask<string> StoreAsync(CredentialEvidence evidence, CancellationToken cancellationToken = default)
    {
        if (failStorage) throw new InvalidOperationException("isolated storage failure");
        Evidence.Enqueue(evidence with { Content = evidence.Content.ToArray() });
        return ValueTask.FromResult("artifact-" + evidence.EventId);
    }
}

internal sealed class AuthenticationByteSession(byte[] input, int fragmentSize = int.MaxValue, bool waitWhenExhausted = false) : IHoneypotSession
{
    private int _offset;
    public string ConnectionId => "conn-auth-test";
    public EndPoint RemoteEndPoint => new IPEndPoint(IPAddress.Loopback, 50000);
    public EndPoint LocalEndPoint => new IPEndPoint(IPAddress.Loopback, 3306);
    public string Transport => "tcp";
    public bool IsClosed { get; private set; }
    public List<byte[]> Writes { get; } = [];
    public async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var count = Math.Min(Math.Min(fragmentSize, buffer.Length), input.Length - _offset);
        if (count == 0 && waitWhenExhausted) await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
        input.AsMemory(_offset, count).CopyTo(buffer); _offset += count; return count;
    }
    public ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken) { Writes.Add(buffer.ToArray()); return ValueTask.CompletedTask; }
    public ValueTask CloseAsync(SessionCloseReason reason, CancellationToken cancellationToken = default) { IsClosed = true; return ValueTask.CompletedTask; }
    public ValueTask DisposeAsync() => ValueTask.CompletedTask;
}
