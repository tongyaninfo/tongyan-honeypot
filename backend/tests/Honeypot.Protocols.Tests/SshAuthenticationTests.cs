using System.Diagnostics;
using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;
using Honeypot.Protocol.Abstractions.Models;
using Honeypot.Protocol.Abstractions.Service;
using Honeypot.Protocols.Common;
using Honeypot.Protocols.Ssh;
using Xunit;

namespace Honeypot.Protocols.Tests;

public sealed class SshAuthenticationTests
{
    [Fact]
    public async Task UnnegotiatedKeyExchangeIsRejectedBeforeAuthentication()
    {
        using var payload = new MemoryStream();
        payload.WriteByte(20);
        payload.Write(new byte[16]);
        foreach (var value in new[] { "unsupported-kex", "rsa-sha2-256", "aes128-ctr", "aes128-ctr", "hmac-sha2-256", "hmac-sha2-256", "none", "none", "", "" })
        {
            var bytes = Encoding.ASCII.GetBytes(value);
            var size = new byte[4]; BinaryPrimitives.WriteInt32BigEndian(size, bytes.Length);
            payload.Write(size); payload.Write(bytes);
        }
        payload.Write(new byte[5]);
        var padding = 8 - ((payload.Length + 5) % 8);
        if (padding < 4) padding += 8;
        var packet = new byte[4 + 1 + payload.Length + padding];
        BinaryPrimitives.WriteInt32BigEndian(packet, packet.Length - 4);
        packet[4] = (byte)padding;
        payload.ToArray().CopyTo(packet, 5);
        var session = new ScriptedSession(Encoding.ASCII.GetBytes("SSH-2.0-isolated-test\r\n").Concat(packet).ToArray());
        var sink = new EvidenceSink();
        await new SshAdapter().HandleAsync(session, TestContext(session), new ServiceProfile { ProfileId = "test", AdapterKey = "ssh" }, sink);
        Assert.True(session.IsClosed);
        Assert.Contains(sink.Events, item => item.EventType == "ProtocolViolation");
        Assert.Empty(sink.Evidence);
    }

    [Fact]
    public async Task StalledHandshakeHonorsTheTotalDeadline()
    {
        var session = new ScriptedSession(null);
        var sink = new EvidenceSink();
        var task = new SshAdapter().HandleAsync(session, TestContext(session), new ServiceProfile
        {
            ProfileId = "test", AdapterKey = "ssh", HandshakeTimeout = TimeSpan.FromMilliseconds(50),
        }, sink).AsTask();
        await task.WaitAsync(TimeSpan.FromSeconds(3));
        Assert.True(session.IsClosed);
        Assert.Contains(sink.Events, item => item.Outcome == "timeout");
        Assert.Empty(sink.Evidence);
    }

    [Theory]
    [InlineData("password", "隔离-test-password-42")]
    [InlineData("keyboard-interactive", "隔离-test-interactive-42")]
    [InlineData("password", "")]
    public async Task OpenSshReceivesPermissionDeniedAndCapturesSubmittedPassword(string method, string password)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var endpoint = (IPEndPoint)listener.LocalEndpoint;
        var sink = new EvidenceSink();
        var server = Task.Run(async () =>
        {
            using var client = await listener.AcceptTcpClientAsync(timeout.Token);
            await using var session = new SocketSession(client);
            await new SshAdapter().HandleAsync(session, Context(session), new ServiceProfile
            {
                ProfileId = "ssh-authentication-test", AdapterKey = "ssh", MaxAuthenticationAttempts = 3,
                HandshakeTimeout = TimeSpan.FromSeconds(8), IdleTimeout = TimeSpan.FromSeconds(12),
            }, sink, timeout.Token);
        }, timeout.Token);
        var start = new ProcessStartInfo("ssh")
        {
            RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true,
            UseShellExecute = false,
        };
        foreach (var arg in new[] { "-F", "/dev/null", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ControlMaster=no", "-o", "ConnectTimeout=8", "-o", "NumberOfPasswordPrompts=2", "-o", "PubkeyAuthentication=no",
            "-o", $"PreferredAuthentications={method}", "-p", endpoint.Port.ToString(), "-l", "capture-user", "127.0.0.1" })
            start.ArgumentList.Add(arg);
        start.Environment["SSH_ASKPASS"] = AskPassPath();
        start.Environment["SSH_ASKPASS_REQUIRE"] = "force";
        start.Environment["DISPLAY"] = ":0";
        start.Environment["HONEYPOT_TEST_PASSWORD"] = password;
        using var process = Process.Start(start)!;
        var stderr = process.StandardError.ReadToEndAsync(timeout.Token);
        var stdout = process.StandardOutput.ReadToEndAsync(timeout.Token);
        try
        {
            await process.WaitForExitAsync(timeout.Token);
            Assert.Equal(255, process.ExitCode);
            Assert.Contains("Permission denied", await stderr, StringComparison.OrdinalIgnoreCase);
            await server.WaitAsync(timeout.Token);
            Assert.Empty(await stdout);
            var auth = sink.Events.Where(item => item.EventType == "AuthenticationAttempted").ToArray();
            Assert.Equal(2, auth.Length);
            Assert.Equal(new int?[] { 1, 2 }, auth.Select(item => item.AuthenticationAttempt));
            foreach (var item in auth)
            {
                Assert.Equal("capture-user", item.Username);
                Assert.Equal(method, item.AuthenticationMethod);
                Assert.Equal("SSH_MSG_USERAUTH_FAILURE", item.AuthenticationFailureCode);
                Assert.Equal("Plaintext", item.MaterialType);
                Assert.Null(item.Password);
                var evidence = Assert.Single(sink.Evidence, value => value.EventId == item.EventId);
                Assert.Equal(evidence.EventId, item.CredentialArtifactId);
                using var content = JsonDocument.Parse(evidence.Content);
                Assert.Equal(password, content.RootElement.GetProperty("password").GetString());
            }
            if (password.Length > 0) Assert.DoesNotContain(password, JsonSerializer.Serialize(sink.Events));
        }
        finally
        {
            if (!process.HasExited) process.Kill(entireProcessTree: true);
            timeout.Cancel();
        }
    }

    private static string AskPassPath([CallerFilePath] string source = "")
        => Path.Combine(Path.GetDirectoryName(source)!, "TestAssets", "ssh-askpass.sh");

    private static ProtocolSessionContext TestContext(IHoneypotSession session) => new(
        session.ConnectionId, "listener-test", "instance-test", "ssh", "profile-test",
        session.RemoteEndPoint, session.LocalEndPoint, DateTimeOffset.UtcNow);

    private sealed class ScriptedSession(byte[]? input) : IHoneypotSession
    {
        private int _offset;
        public string ConnectionId => "scripted-ssh-test";
        public EndPoint RemoteEndPoint => new IPEndPoint(IPAddress.Loopback, 23456);
        public EndPoint LocalEndPoint => new IPEndPoint(IPAddress.Loopback, 22);
        public string Transport => "tcp";
        public bool IsClosed { get; private set; }
        public async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct)
        {
            if (input is null) { await Task.Delay(Timeout.Infinite, ct); return 0; }
            if (_offset == input.Length) return 0;
            // 每次仅返回一个字节，保证适配器不依赖 TCP 报文边界。
            buffer.Span[0] = input[_offset++]; return 1;
        }
        public ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct) => ValueTask.CompletedTask;
        public ValueTask CloseAsync(SessionCloseReason reason, CancellationToken ct = default)
        { IsClosed = true; return ValueTask.CompletedTask; }
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    internal static ProtocolSessionContext Context(SocketSession session, string adapter = "ssh") => new(
        session.ConnectionId, "listener-test", "instance-test", adapter, "profile-test",
        session.RemoteEndPoint, session.LocalEndPoint, DateTimeOffset.UtcNow);

    internal sealed class SocketSession(TcpClient client) : IHoneypotSession, IRawStreamHoneypotSession
    {
        public string ConnectionId => "connection-authentication-test";
        public EndPoint RemoteEndPoint { get; } = client.Client.RemoteEndPoint!;
        public EndPoint LocalEndPoint { get; } = client.Client.LocalEndPoint!;
        public string Transport => "tcp";
        public bool IsClosed { get; private set; }
        public Stream RawStream { get; } = client.GetStream();
        public ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct) => RawStream.ReadAsync(buffer, ct);
        public ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct) => RawStream.WriteAsync(buffer, ct);
        public ValueTask CloseAsync(SessionCloseReason reason, CancellationToken ct = default)
        { IsClosed = true; client.Close(); return ValueTask.CompletedTask; }
        public ValueTask DisposeAsync() { client.Dispose(); return ValueTask.CompletedTask; }
    }

    internal sealed class EvidenceSink : IInteractionEventSink, ICredentialEvidenceSink
    {
        public List<InteractionEvent> Events { get; } = [];
        public List<CredentialEvidence> Evidence { get; } = [];
        public ValueTask<EventAppendResult> AppendAsync(InteractionEvent item, CancellationToken ct = default)
        { Events.Add(item); return ValueTask.FromResult(EventAppendResult.Accepted()); }
        public ValueTask<string> StoreAsync(CredentialEvidence evidence, CancellationToken ct = default)
        { Evidence.Add(evidence); return ValueTask.FromResult(evidence.EventId); }
    }
}
