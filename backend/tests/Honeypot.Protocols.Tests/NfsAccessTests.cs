using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using Honeypot.Protocols.Nfs;
using Xunit;

namespace Honeypot.Protocols.Tests;

public sealed class NfsAccessTests
{
    [Theory]
    [InlineData(9)]
    [InlineData(15)]
    public async Task V41NegotiatesThenReturnsAccessDeniedWithoutPasswordOrAuthenticationAttempt(uint operation)
    {
        await using var server = new AuthenticationTestServer(new NfsAdapter(), AuthenticationTestServer.Profile("nfs"));
        using var client = new TcpClient(); await client.ConnectAsync(IPAddress.Loopback, server.Port);
        using var stream = client.GetStream();
        var exchange = Compound(1, w => { w.UInt(42); w.Raw(new byte[8]); w.Text("isolated-client"); w.UInt(0); w.UInt(0); w.UInt(0); });
        // TCP 字节分片以及 RPC record 分段均独立验证。
        var response = await Call(stream, 1, exchange, splitRecord: true);
        Assert.Equal(0u, UInt(response, 24));
        var clientId = BinaryPrimitives.ReadUInt64BigEndian(response.AsSpan(44));
        var create = Compound(1, w =>
        {
            w.UInt(43); w.ULong(clientId); w.UInt(1); w.UInt(0);
            Channel(w); Channel(w); w.UInt(0); w.UInt(1); w.UInt(0);
        });
        response = await Call(stream, 2, create);
        Assert.Equal(0u, UInt(response, 24));
        var sessionId = response.AsSpan(44, 16).ToArray();
        var access = Compound(3, w =>
        {
            w.UInt(53); w.Raw(sessionId); w.UInt(1); w.UInt(0); w.UInt(0); w.UInt(1);
            w.UInt(24); w.UInt(operation);
            if (operation == 9) { w.UInt(1); w.UInt(2); }
            else w.Text("sample-export");
        });
        response = await Call(stream, 3, access);
        Assert.Equal(13u, UInt(response, 24)); // NFS4ERR_ACCESS
        Assert.Equal(3u, UInt(response, 32));
        var denied = Assert.Single(server.Sink.Events, e => e.EventType == "AuthorizationDenied");
        Assert.Equal("uid:1001", denied.Username); Assert.Equal("AUTH_SYS", denied.AuthenticationMethod);
        Assert.Equal("NFS4ERR_ACCESS", denied.AuthenticationFailureCode); Assert.Null(denied.AuthenticationAttempt);
        Assert.Null(denied.Password); Assert.DoesNotContain(server.Sink.Events, e => e.EventType == "AuthenticationAttempted");
        var artifact = Assert.Single(server.Sink.Evidence);
        Assert.Equal(denied.EventId, artifact.EventId); Assert.Equal("Identity", artifact.MaterialType);
        using var content = JsonDocument.Parse(artifact.Content);
        Assert.Equal(1001u, content.RootElement.GetProperty("Uid").GetUInt32());
        Assert.False(content.RootElement.GetProperty("identityVerified").GetBoolean());
        Assert.False(content.RootElement.TryGetProperty("password", out _));
        Assert.Empty(server.Errors);
    }

    [Fact]
    public async Task RpcNullProbeDoesNotBecomeAnAuthenticationAttempt()
    {
        await using var server = new AuthenticationTestServer(new NfsAdapter(), AuthenticationTestServer.Profile("nfs"));
        using var client = new TcpClient(); await client.ConnectAsync(IPAddress.Loopback, server.Port);
        using var stream = client.GetStream();
        var result = await Call(stream, 8, [], procedure: 0);
        Assert.Equal(24, result.Length); Assert.Equal(0u, UInt(result, 20));
        Assert.Empty(server.Sink.Evidence); Assert.Empty(server.Sink.Events);
    }

    [Fact]
    public async Task GssTokenReceivesRpcAuthenticationRejectionAndRemainsResponseMaterial()
    {
        await using var server = new AuthenticationTestServer(new NfsAdapter(), AuthenticationTestServer.Profile("nfs"));
        using var client = new TcpClient(); await client.ConnectAsync(IPAddress.Loopback, server.Port);
        using var stream = client.GetStream();
        var result = await Call(stream, 9, [0, 0, 0, 0], flavor: 6);
        Assert.Equal(1u, UInt(result, 8)); Assert.Equal(1u, UInt(result, 12)); Assert.Equal(13u, UInt(result, 16));
        var denied = Assert.Single(server.Sink.Events, e => e.EventType == "AuthorizationDenied");
        Assert.Equal("RPCSEC_GSS", denied.AuthenticationMethod); Assert.Equal("Response", denied.MaterialType);
        Assert.Null(denied.Username); Assert.Null(denied.Password);
        Assert.DoesNotContain(server.Sink.Events, e => e.EventType == "AuthenticationAttempted");
    }

    [Fact]
    public async Task OversizedRpcRecordIsRejectedBeforeAllocationOrEvidence()
    {
        await using var session = new AuthenticationByteSession([0xFF, 0xFF, 0xFF, 0xFF], fragmentSize: 1);
        var sink = new AuthenticationRecordingSink();
        await new NfsAdapter().HandleAsync(session, AuthenticationTestServer.Context("nfs"), AuthenticationTestServer.Profile("nfs"), sink);
        Assert.Empty(sink.Evidence); Assert.Contains(sink.Events, e => e.EventType == "ProtocolViolation");
    }

    private static byte[] Compound(uint count, Action<Writer> write)
    {
        var writer = new Writer(); writer.Text(""); writer.UInt(1); writer.UInt(count); write(writer); return writer.Bytes();
    }
    private static void Channel(Writer w) { foreach (uint n in new uint[] { 0, 65536, 65536, 65536, 16, 1, 0 }) w.UInt(n); }
    private static async Task<byte[]> Call(Stream stream, uint xid, byte[] body, uint procedure = 1, uint flavor = 1, bool splitRecord = false)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(4));
        var identity = new Writer(); identity.UInt(0); identity.Text("isolated-client"); identity.UInt(1001); identity.UInt(100); identity.UInt(1); identity.UInt(100);
        var request = new Writer(); request.UInt(xid); request.UInt(0); request.UInt(2); request.UInt(100003); request.UInt(4); request.UInt(procedure);
        request.UInt(flavor); request.Opaque(identity.Bytes()); request.UInt(0); request.UInt(0); request.Raw(body);
        var payload = request.Bytes();
        if (splitRecord)
        {
            var frame = new Writer(); frame.UInt(7); frame.Raw(payload[..7]); frame.UInt(0x80000000u | (uint)(payload.Length - 7)); frame.Raw(payload[7..]);
            foreach (var value in frame.Bytes()) await stream.WriteAsync(new[] { value }, timeout.Token);
        }
        else
        {
            var frame = new Writer(); frame.UInt(0x80000000u | (uint)payload.Length); frame.Raw(payload); await stream.WriteAsync(frame.Bytes(), timeout.Token);
        }
        var header = new byte[4]; await stream.ReadExactlyAsync(header, timeout.Token);
        var length = UInt(header, 0) & 0x7FFFFFFF; Assert.InRange(length, 16u, 65536u);
        var response = new byte[length]; await stream.ReadExactlyAsync(response, timeout.Token); Assert.Equal(xid, UInt(response, 0));
        return response;
    }
    private static uint UInt(byte[] data, int offset) => BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(offset));
    private sealed class Writer
    {
        private readonly MemoryStream _stream = new();
        public void UInt(uint n) { var b = new byte[4]; BinaryPrimitives.WriteUInt32BigEndian(b, n); _stream.Write(b); }
        public void ULong(ulong n) { UInt((uint)(n >> 32)); UInt((uint)n); }
        public void Raw(byte[] data) => _stream.Write(data);
        public void Opaque(byte[] data) { UInt((uint)data.Length); Raw(data); Raw(new byte[(4 - data.Length % 4) % 4]); }
        public void Text(string text) => Opaque(Encoding.UTF8.GetBytes(text));
        public byte[] Bytes() => _stream.ToArray();
    }
}
