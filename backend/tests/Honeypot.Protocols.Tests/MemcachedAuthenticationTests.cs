using System.Buffers.Binary;
using System.Text;
using System.Text.Json;
using Honeypot.Protocols.Memcached;
using Xunit;

namespace Honeypot.Protocols.Tests;

public sealed class MemcachedAuthenticationTests
{
    [Theory]
    [InlineData(false, "isolated-password-雪")]
    [InlineData(true, "")]
    public async Task SaslMechanismsAndPlainAuthenticationHaveMatchingOpaque(bool step, string password)
    {
        var input = new List<byte>();
        input.AddRange(Packet(0x20, "", []));
        if (step) input.AddRange(Packet(0x21, "PLAIN", []));
        input.AddRange(Packet(step ? (byte)0x22 : (byte)0x21, "PLAIN", Encoding.UTF8.GetBytes("\0隔离用户\0" + password)));
        var session = new AuthenticationByteSession(input.ToArray(), 1);
        var sink = new AuthenticationRecordingSink();
        await new MemcachedAdapter().HandleAsync(session, AuthenticationTestServer.Context("memcached"), AuthenticationTestServer.Profile("memcached"), sink);
        Assert.Equal("PLAIN", Encoding.UTF8.GetString(session.Writes[0], 24, session.Writes[0].Length - 24));
        var reply = session.Writes[^1];
        Assert.Equal(0x81, reply[0]);
        Assert.Equal(0x20, BinaryPrimitives.ReadUInt16BigEndian(reply.AsSpan(6)));
        Assert.Equal(0x12345678u, BinaryPrimitives.ReadUInt32BigEndian(reply.AsSpan(12)));
        var authentication = Assert.Single(sink.Events, x => x.EventType == "AuthenticationAttempted");
        Assert.Equal("隔离用户", authentication.Username);
        Assert.Equal("SASL PLAIN", authentication.AuthenticationMethod);
        using var json = JsonDocument.Parse(Assert.Single(sink.Evidence).Content);
        Assert.Equal(password, json.RootElement.GetProperty("password").GetString());
        Assert.DoesNotContain("isolated-password", JsonSerializer.Serialize(sink.Events), StringComparison.Ordinal);
    }

    [Fact]
    public async Task UnsupportedMechanismIsEvidenceNotUnboundedEventText()
    {
        var session = new AuthenticationByteSession(Packet(0x21, "ISOLATED-SECRET", "isolated-response"u8.ToArray()), 1);
        var sink = new AuthenticationRecordingSink();
        await new MemcachedAdapter().HandleAsync(session, AuthenticationTestServer.Context("memcached"), AuthenticationTestServer.Profile("memcached"), sink);
        var authentication = Assert.Single(sink.Events, x => x.EventType == "AuthenticationAttempted");
        Assert.Equal("SASL unsupported", authentication.AuthenticationMethod);
        Assert.Equal("Response", authentication.MaterialType);
        Assert.DoesNotContain("ISOLATED-SECRET", JsonSerializer.Serialize(sink.Events), StringComparison.Ordinal);
        using var json = JsonDocument.Parse(Assert.Single(sink.Evidence).Content);
        Assert.Equal("ISOLATED-SECRET", json.RootElement.GetProperty("mechanism").GetString());
        Assert.Equal(JsonValueKind.Null, json.RootElement.GetProperty("password").ValueKind);
    }

    [Fact]
    public async Task OversizedBinaryBodyIsRejectedBeforeAllocation()
    {
        var header = Packet(0x21, "", []);
        BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(8), uint.MaxValue);
        var session = new AuthenticationByteSession(header, 1);
        var sink = new AuthenticationRecordingSink();
        await new MemcachedAdapter().HandleAsync(session, AuthenticationTestServer.Context("memcached"), AuthenticationTestServer.Profile("memcached"), sink);
        Assert.Empty(sink.Evidence);
        Assert.Contains(sink.Events, x => x.EventType == "ProtocolViolation");
    }

    private static byte[] Packet(byte opcode, string mechanism, byte[] body)
    {
        var key = Encoding.ASCII.GetBytes(mechanism);
        var packet = new byte[24 + key.Length + body.Length]; packet[0] = 0x80; packet[1] = opcode;
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2), (ushort)key.Length);
        BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(8), (uint)(key.Length + body.Length));
        BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(12), 0x12345678u);
        key.CopyTo(packet, 24); body.CopyTo(packet, 24 + key.Length); return packet;
    }
}
