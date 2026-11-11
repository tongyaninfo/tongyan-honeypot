using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using Honeypot.Protocol.Abstractions.Service;
using Honeypot.Protocol.Abstractions.Models;
using Honeypot.Protocols.Db2;
using Honeypot.Protocols.HBase;
using Honeypot.Protocols.Oracle;
using Xunit;

namespace Honeypot.Protocols.Tests;

public sealed class EnterpriseAuthenticationTests
{
    [Theory]
    [InlineData("db2")]
    [InlineData("oracle")]
    [InlineData("hbase")]
    public async Task HandshakeDeadlineIsDiagnosedWithoutInventingAuthentication(string key)
    {
        var session = new TrackedSession([], true);
        var sink = new AuthenticationRecordingSink();
        await Adapter(key).HandleAsync(session, AuthenticationTestServer.Context(key),
            AuthenticationTestServer.Profile(key) with { HandshakeTimeout = TimeSpan.FromMilliseconds(60) }, sink);
        Assert.Equal(SessionCloseReason.HandshakeTimeout, session.CloseReason);
        Assert.Contains(sink.Events, e => e.EventType == "HandshakeTimeout");
        Assert.Empty(sink.Evidence);
    }

    [Theory]
    [InlineData("db2")]
    [InlineData("oracle")]
    [InlineData("hbase")]
    public async Task InvalidFrameLengthIsDiagnosed(string key)
    {
        var input = key switch
        {
            "db2" => new byte[] { 0, 5, 0xd0, 1, 0, 1 },
            "oracle" => new byte[] { 0, 7, 0, 0, 1, 0, 0, 0 },
            _ => new byte[] { 72, 66, 97, 115, 0, 82, 255, 255, 255, 255 },
        };
        var session = new TrackedSession(input);
        var sink = new AuthenticationRecordingSink();
        await Adapter(key).HandleAsync(session, AuthenticationTestServer.Context(key), AuthenticationTestServer.Profile(key), sink);
        Assert.Equal(SessionCloseReason.ProtocolViolation, session.CloseReason);
        Assert.Contains(sink.Events, e => e.EventType == "ProtocolViolation");
        Assert.Empty(sink.Evidence);
    }

    [Fact]
    public async Task HBaseSimpleAuthUsesRpcProtobufRejection()
    {
        var session = new AuthenticationByteSession([72, 66, 97, 115, 0, 80]);
        var sink = new AuthenticationRecordingSink();
        await new HBaseAdapter().HandleAsync(session, AuthenticationTestServer.Context("hbase"), AuthenticationTestServer.Profile("hbase"), sink);
        var packet = Assert.Single(session.Writes);
        Assert.Equal(packet.Length - 4, BinaryPrimitives.ReadInt32BigEndian(packet));
        Assert.Contains("org.apache.hadoop.hbase.security.AccessDeniedException", Encoding.UTF8.GetString(packet));
        Assert.Contains("Authentication is required", Encoding.UTF8.GetString(packet));
        Assert.Empty(sink.Evidence);
    }
    [Theory]
    [InlineData("db2")]
    [InlineData("oracle")]
    [InlineData("hbase")]
    public async Task InvalidPreambleNeverBecomesCredential(string key)
    {
        var session = new AuthenticationByteSession(key switch
        {
            "db2" => [0, 10, 0xff, 1, 0, 1, 0, 4, 0, 0],
            "oracle" => [0, 8, 0, 0, 1, 0, 0, 0],
            _ => [72, 66, 97, 115, 1, 82],
        }, 1);
        var sink = new AuthenticationRecordingSink();
        await Adapter(key).HandleAsync(session, AuthenticationTestServer.Context(key), AuthenticationTestServer.Profile(key), sink);
        Assert.Contains(sink.Events, e => e.EventType == "ProtocolViolation");
        Assert.Empty(sink.Evidence);
        Assert.DoesNotContain(sink.Events, e => e.EventType == "AuthenticationAttempted");
        Assert.True(session.IsClosed);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(4096)]
    public async Task Db2CleartextExchangeRejectsOnceAndPreservesEvidence(int fragment)
    {
        Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
        var encoding = Encoding.GetEncoding(37);
        var input = Db2Packet(1, 0x1041, Ddm(0x1404, []))
            .Concat(Db2Packet(2, 0x106d, Ddm(0x11a2, [0, 3]), Ddm(0x2110, encoding.GetBytes("SAMPLE"))))
            .Concat(Db2Packet(1, 0x106e, Ddm(0x11a2, [0, 3]), Ddm(0x11a0, encoding.GetBytes("isolated_user")),
                Ddm(0x11a1, encoding.GetBytes("isolated-secret")))).ToArray();
        var session = new AuthenticationByteSession(input, fragment);
        var sink = new AuthenticationRecordingSink();
        await new Db2Adapter().HandleAsync(session, AuthenticationTestServer.Context("db2"), AuthenticationTestServer.Profile("db2"), sink);
        var attempt = Assert.Single(sink.Events, e => e.EventType == "AuthenticationAttempted");
        Assert.Equal("isolated_user", attempt.Username);
        Assert.Equal("SECCHKCD_0F", attempt.AuthenticationFailureCode);
        Assert.Equal("SAMPLE", attempt.Database);
        Assert.Equal("Plaintext", attempt.MaterialType);
        var evidence = Assert.Single(sink.Evidence);
        Assert.Equal(attempt.EventId, evidence.EventId);
        using var json = JsonDocument.Parse(evidence.Content);
        Assert.Equal("isolated-secret", json.RootElement.GetProperty("password").GetString());
        Assert.DoesNotContain("isolated-secret", JsonSerializer.Serialize(sink.Events));
        Assert.Equal(3, session.Writes.Count);
        Assert.Equal(0x0f, session.Writes[^1][^1]);
    }

    [Fact]
    public async Task Db2InvalidDhPublicValueDoesNotRecordAuthentication()
    {
        var input = Db2Packet(1, 0x1041).Concat(Db2Packet(2, 0x106d,
            Ddm(0x11a2, [0, 9]), Ddm(0x11dc, new byte[64]))).ToArray();
        var session = new AuthenticationByteSession(input, 1);
        var sink = new AuthenticationRecordingSink();
        await new Db2Adapter().HandleAsync(session, AuthenticationTestServer.Context("db2"), AuthenticationTestServer.Profile("db2"), sink);
        Assert.Contains(sink.Events, e => e.EventType == "ProtocolViolation");
        Assert.Empty(sink.Evidence);
    }

    [Fact]
    public async Task HBaseDigestResponseIsAnAuthenticationFailureNotPlaintextPassword()
    {
        await using var server = new AuthenticationTestServer(new HBaseAdapter(), AuthenticationTestServer.Profile("hbase"));
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, server.Port);
        var stream = client.GetStream();
        await stream.WriteAsync(new byte[] { 72, 66, 97, 115, 0, 82, 0, 0, 0, 0 });
        var prefix = new byte[8]; await stream.ReadExactlyAsync(prefix);
        Assert.Equal(0, BinaryPrimitives.ReadInt32BigEndian(prefix));
        var challenge = new byte[BinaryPrimitives.ReadInt32BigEndian(prefix.AsSpan(4))]; await stream.ReadExactlyAsync(challenge);
        var text = Encoding.UTF8.GetString(challenge);
        var nonce = text.Split("nonce=\"")[1].Split('"')[0];
        var token = Convert.ToBase64String(new byte[] { 0, 0, 0, 8, 8, 0, 18, 4, 117, 115, 101, 114 });
        var response = Encoding.UTF8.GetBytes($"username=\"{token}\",realm=\"default\",nonce=\"{nonce}\",cnonce=\"fixture\",nc=00000001,qop=auth,digest-uri=\"hbase/localhost\",response=00000000000000000000000000000000");
        var length = new byte[4]; BinaryPrimitives.WriteInt32BigEndian(length, response.Length);
        await stream.WriteAsync(length); await stream.WriteAsync(response);
        await stream.ReadExactlyAsync(length);
        Assert.Equal(1, BinaryPrimitives.ReadInt32BigEndian(length));
        var auth = await server.Sink.Authentication.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal("user", auth.Username); Assert.Equal("Response", auth.MaterialType);
        var evidence = Assert.Single(server.Sink.Evidence);
        using var json = JsonDocument.Parse(evidence.Content);
        Assert.Equal(JsonValueKind.Null, json.RootElement.GetProperty("password").ValueKind);
        Assert.Equal(auth.EventId, evidence.EventId);
        Assert.Single(server.Sink.Events, e => e.EventType == "AuthenticationAttempted");
        Assert.Empty(server.Errors);
    }

    [Fact]
    public async Task HBaseEmptyKerberosTokenDoesNotInventIdentity()
    {
        var session = new AuthenticationByteSession([72, 66, 97, 115, 0, 81, 0, 0, 0, 0], 1);
        var sink = new AuthenticationRecordingSink();
        await new HBaseAdapter().HandleAsync(session, AuthenticationTestServer.Context("hbase"), AuthenticationTestServer.Profile("hbase"), sink);
        Assert.Empty(sink.Evidence); Assert.Contains(sink.Events, e => e.EventType == "ProtocolViolation");
    }

    [Fact]
    public async Task OracleHandshakeOnlyDoesNotInventCredential()
    {
        var connect = new byte[74];
        BinaryPrimitives.WriteUInt16BigEndian(connect, 74); connect[4] = 1;
        BinaryPrimitives.WriteUInt16BigEndian(connect.AsSpan(26), 74);
        var session = new AuthenticationByteSession(connect, 1);
        var sink = new AuthenticationRecordingSink();
        await new OracleAdapter().HandleAsync(session, AuthenticationTestServer.Context("oracle"), AuthenticationTestServer.Profile("oracle"), sink);
        Assert.Single(session.Writes); Assert.Equal(2, session.Writes[0][4]);
        Assert.Empty(sink.Evidence); Assert.DoesNotContain(sink.Events, e => e.EventType == "AuthenticationAttempted");
    }

    private static IHoneypotServiceAdapter Adapter(string key) => key switch { "db2" => new Db2Adapter(), "oracle" => new OracleAdapter(), _ => new HBaseAdapter() };
    private static byte[] Db2Packet(ushort id, ushort command, params byte[][] fields)
    {
        var ddm = Ddm(command, fields.SelectMany(b => b).ToArray());
        var result = new byte[6 + ddm.Length]; BinaryPrimitives.WriteUInt16BigEndian(result, (ushort)result.Length);
        result[2] = 0xd0; result[3] = 1; BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(4), id); ddm.CopyTo(result, 6); return result;
    }
    private static byte[] Ddm(ushort code, byte[] value)
    {
        var result = new byte[4 + value.Length]; BinaryPrimitives.WriteUInt16BigEndian(result, (ushort)result.Length);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(2), code); value.CopyTo(result, 4); return result;
    }

    private sealed class TrackedSession(byte[] input, bool wait = false) : IHoneypotSession
    {
        private readonly AuthenticationByteSession _inner = new(input, 1, wait);
        public SessionCloseReason? CloseReason { get; private set; }
        public string ConnectionId => _inner.ConnectionId;
        public EndPoint RemoteEndPoint => _inner.RemoteEndPoint;
        public EndPoint LocalEndPoint => _inner.LocalEndPoint;
        public string Transport => _inner.Transport;
        public bool IsClosed => _inner.IsClosed;
        public ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct) => _inner.ReadAsync(buffer, ct);
        public ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct) => _inner.WriteAsync(buffer, ct);
        public ValueTask CloseAsync(SessionCloseReason reason, CancellationToken ct = default) { CloseReason = reason; return _inner.CloseAsync(reason, ct); }
        public ValueTask DisposeAsync() => _inner.DisposeAsync();
    }
}
