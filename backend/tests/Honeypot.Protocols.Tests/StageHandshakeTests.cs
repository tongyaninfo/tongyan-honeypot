using System.Net;
using System.Text;
using Honeypot.Protocol.Abstractions.Models;
using Honeypot.Protocol.Abstractions.Service;
using Honeypot.Protocols.Common;
using Honeypot.Protocols.MsSql;
using Honeypot.Protocols.Rdp;
using Honeypot.Protocols.Mongo;
using Xunit;
using MongoDB.Bson;

namespace Honeypot.Protocols.Tests;

public sealed class StageHandshakeTests
{
    [Fact]
    public async Task MongoHelloThenSaslReturnsAuthenticationFailure()
    {
        var hello = MongoPacket(7, "hello");
        var auth = MongoPacket(8, "saslStart");
        var session = new QueueSession(hello, auth);
        var sink = new RecordingSink();

        await new MongoAdapter().HandleAsync(session, Context("mongodb"), Profile("mongodb"), sink);

        Assert.True(session.Writes.Count >= 2);
        Assert.Contains(sink.Events, item => item.EventType == "AuthenticationAttempted" && item.Outcome == "failure");
        Assert.Equal(1, sink.StoredCount);
    }

    [Fact]
    public async Task MsSqlPreLoginReturnsTdsResponseAndRejectsLogin()
    {
        // 隔离报文测试显式 ENCRYPT_NOT_SUP；真实驱动 TLS 由 MsSqlAuthenticationTests 覆盖。
        var prelogin = TdsPacket(0x12, new byte[] { 0, 0, 11, 0, 6, 1, 0, 17, 0, 1, 0xFF, 15, 0, 0, 0, 0, 0, 2 });
        var loginPayload = new byte[98];
        BitConverter.GetBytes((uint)loginPayload.Length).CopyTo(loginPayload, 0);
        BitConverter.GetBytes(0x74000004u).CopyTo(loginPayload, 4);
        BitConverter.GetBytes(4096u).CopyTo(loginPayload, 8);
        // LOGIN7 的 36 是 HostName，40 才是 UserName；固定头为 94 字节。
        BitConverter.GetBytes((ushort)94).CopyTo(loginPayload, 40);
        BitConverter.GetBytes((ushort)2).CopyTo(loginPayload, 42);
        Encoding.Unicode.GetBytes("sa").CopyTo(loginPayload, 94);
        var login = TdsPacket(0x10, loginPayload);
        var session = new QueueSession(prelogin, login);
        var sink = new RecordingSink();

        await new MsSqlAdapter().HandleAsync(session, Context("mssql"), Profile("mssql"), sink);

        Assert.True(session.Writes.Count >= 2);
        Assert.Equal(0x04, session.Writes[0][0]);
        Assert.Contains(sink.Events, item => item.EventType == "AuthenticationAttempted" && item.Username == "sa");
        Assert.Equal(1, sink.StoredCount);
    }

    [Fact]
    public async Task RdpWithoutNlaReceivesNegotiationFailure()
    {
        var request = new byte[] { 0x03, 0x00, 0x00, 0x13, 0x0E, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00 };
        var mcs = new byte[] { 0x03, 0x00, 0x00, 0x0B, 0x02, 0xF0, 0x80, 0x00, 0x00, 0x00, 0x00 };
        var session = new QueueSession(request, mcs);
        var sink = new RecordingSink();

        await new RdpAdapter().HandleAsync(session, Context("rdp"), Profile("rdp"), sink);

        Assert.Single(session.Writes);
        Assert.Equal(3, session.Writes[0][11]);
        Assert.DoesNotContain(sink.Events, item => item.EventType == "AuthenticationAttempted");
        Assert.Contains(sink.Events, item => item.EventType == "ProtocolViolation");
    }

    [Fact]
    public void CredSspParsesNtlmType3IdentityAndBuildsFailure()
    {
        var type3 = BuildNtlmType3("CONTOSO", "alice", "WIN-CLIENT");

        Assert.True(CredSspProtocol.TryParseNtlm(type3, out var parsed));
        Assert.Equal((uint)3, parsed.Type);
        Assert.Equal("CONTOSO", parsed.Domain);
        Assert.Equal("alice", parsed.Username);
        Assert.Equal("WIN-CLIENT", parsed.Workstation);
        Assert.Equal(24, parsed.NtResponse?.Length);

        var failure = CredSspProtocol.BuildAuthenticationFailure();
        Assert.Equal((byte)0x30, failure[0]);
        Assert.Contains((byte)0xA4, failure);
        Assert.Contains((byte)0xC0, failure);
    }

    [Fact]
    public void CredSspChallengeRoundTripsThroughSpnegoToken()
    {
        var challenge = CredSspProtocol.BuildNtlmChallenge("WIN-RDP-01", 0);
        var request = CredSspProtocol.BuildSpnegoChallenge(challenge);

        Assert.True(CredSspProtocol.TryExtractNtlmToken(request, out var extracted));
        Assert.Equal(challenge, extracted);
    }

    private static ProtocolSessionContext Context(string adapter) => new(
        "conn-stage", "listener-stage", "instance-stage", adapter, "profile-stage",
        new IPEndPoint(IPAddress.Parse("192.0.2.10"), 50000),
        new IPEndPoint(IPAddress.Loopback, 3306), DateTimeOffset.UtcNow);

    private static ServiceProfile Profile(string adapter) => new()
    {
        ProfileId = "profile-stage",
        AdapterKey = adapter,
        AuthMode = "AlwaysFail",
        CredentialEvidenceEncryptionKeyRef = "test-key",
    };

    private static byte[] MongoPacket(int requestId, string text)
    {
        var document = text == "saslStart"
            ? new BsonDocument { { "saslStart", 1 }, { "mechanism", "PLAIN" }, { "payload", new BsonBinaryData(Encoding.UTF8.GetBytes("\0test-user\0test-password")) }, { "$db", "admin" } }
            : new BsonDocument { { text, 1 }, { "$db", "admin" } };
        var body = document.ToBson();
        var packet = new byte[21 + body.Length];
        BitConverter.GetBytes(packet.Length).CopyTo(packet, 0);
        BitConverter.GetBytes(requestId).CopyTo(packet, 4);
        BitConverter.GetBytes(2013).CopyTo(packet, 12);
        body.CopyTo(packet, 21);
        return packet;
    }

    private static byte[] TdsPacket(byte type, byte[] payload)
    {
        var packet = new byte[8 + payload.Length];
        packet[0] = type;
        packet[1] = 1;
        packet[2] = (byte)(packet.Length >> 8);
        packet[3] = (byte)packet.Length;
        packet[6] = 1;
        payload.CopyTo(packet, 8);
        return packet;
    }

    private static byte[] BuildNtlmType3(string domain, string user, string workstation)
    {
        var domainBytes = Encoding.Unicode.GetBytes(domain);
        var userBytes = Encoding.Unicode.GetBytes(user);
        var workstationBytes = Encoding.Unicode.GetBytes(workstation);
        var lm = new byte[24];
        var nt = new byte[24];
        var payloadOffset = 64;
        var message = new byte[payloadOffset + lm.Length + nt.Length + domainBytes.Length + userBytes.Length + workstationBytes.Length];
        Encoding.ASCII.GetBytes("NTLMSSP\0").CopyTo(message, 0);
        BitConverter.GetBytes(3u).CopyTo(message, 8);
        WriteBuffer(message, 12, lm.Length, payloadOffset); payloadOffset += lm.Length;
        WriteBuffer(message, 20, nt.Length, payloadOffset); payloadOffset += nt.Length;
        WriteBuffer(message, 28, domainBytes.Length, payloadOffset); domainBytes.CopyTo(message, payloadOffset); payloadOffset += domainBytes.Length;
        WriteBuffer(message, 36, userBytes.Length, payloadOffset); userBytes.CopyTo(message, payloadOffset); payloadOffset += userBytes.Length;
        WriteBuffer(message, 44, workstationBytes.Length, payloadOffset); workstationBytes.CopyTo(message, payloadOffset); payloadOffset += workstationBytes.Length;
        WriteBuffer(message, 52, 0, payloadOffset);
        BitConverter.GetBytes(1u).CopyTo(message, 60);
        return message;
    }

    private static void WriteBuffer(byte[] message, int offset, int length, int dataOffset)
    {
        BitConverter.GetBytes((ushort)length).CopyTo(message, offset);
        BitConverter.GetBytes((ushort)length).CopyTo(message, offset + 2);
        BitConverter.GetBytes((uint)dataOffset).CopyTo(message, offset + 4);
    }


    private sealed class QueueSession : IHoneypotSession
    {
        private readonly Queue<byte[]> _reads;
        private byte[]? _current;
        private int _offset;
        public QueueSession(params byte[][] reads) => _reads = new Queue<byte[]>(reads);
        public string ConnectionId => "conn-stage";
        public EndPoint RemoteEndPoint => new IPEndPoint(IPAddress.Parse("192.0.2.10"), 50000);
        public EndPoint LocalEndPoint => new IPEndPoint(IPAddress.Loopback, 3306);
        public string Transport => "tcp";
        public bool IsClosed { get; private set; }
        public List<byte[]> Writes { get; } = new();
        public ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken)
        {
            if (_current is null || _offset >= _current.Length)
            {
                if (_reads.Count == 0) return ValueTask.FromResult(0);
                _current = _reads.Dequeue();
                _offset = 0;
            }
            var count = Math.Min(buffer.Length, _current.Length - _offset);
            _current.AsMemory(_offset, count).CopyTo(buffer);
            _offset += count;
            return ValueTask.FromResult(count);
        }
        public ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken)
        {
            Writes.Add(buffer.ToArray());
            return ValueTask.CompletedTask;
        }
        public ValueTask CloseAsync(SessionCloseReason reason, CancellationToken cancellationToken = default)
        {
            IsClosed = true;
            return ValueTask.CompletedTask;
        }
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    private sealed class RecordingSink : IInteractionEventSink, ICredentialEvidenceSink
    {
        public List<InteractionEvent> Events { get; } = new();
        public int StoredCount { get; private set; }
        public ValueTask<EventAppendResult> AppendAsync(InteractionEvent interactionEvent, CancellationToken cancellationToken = default)
        {
            Events.Add(interactionEvent);
            return ValueTask.FromResult(EventAppendResult.Accepted());
        }
        public ValueTask<string> StoreAsync(CredentialEvidence evidence, CancellationToken cancellationToken = default)
        {
            StoredCount++;
            return ValueTask.FromResult("credential-test");
        }
    }
}
