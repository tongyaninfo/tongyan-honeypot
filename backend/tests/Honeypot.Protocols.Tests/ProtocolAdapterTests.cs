using Xunit;
using System.Net;
using System.Text;
using Honeypot.Protocol.Abstractions.Models;
using Honeypot.Protocol.Abstractions.Service;
using Honeypot.Protocols.Common;
using Honeypot.Protocols.Mongo;
using Honeypot.Protocols.MySql;
using Honeypot.Protocols.Ssh;
using MongoDB.Bson;

namespace Honeypot.Protocols.Tests;

public sealed class ProtocolAdapterTests
{
    [Fact]
    public async Task SshSendsBannerAndClosesIdleSession()
    {
        var session = new FakeSession(Array.Empty<byte>());
        var sink = new FakeSink();
        await new SshAdapter().HandleAsync(session, Context("ssh"), Profile("ssh"), sink);
        Assert.Contains(session.Writes, x => Encoding.ASCII.GetString(x).StartsWith("SSH-2.0-", StringComparison.Ordinal));
        Assert.Contains(sink.Events, x => x.EventType == "BannerSent");
    }

    [Fact]
    public async Task SshUsesRealisticDefaultFingerprint()
    {
        var session = new FakeSession(Array.Empty<byte>());
        await new SshAdapter().HandleAsync(session, Context("ssh"), new ServiceProfile
        {
            ProfileId = "profile-default-ssh",
            AdapterKey = "ssh",
        }, new FakeSink());

        var banner = Encoding.ASCII.GetString(session.Writes[0]);
        Assert.StartsWith("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5", banner, StringComparison.Ordinal);
    }

    [Fact]
    public async Task MysqlMalformedInitialPacketDoesNotCountAsAuthentication()
    {
        var response = new byte[64];
        Encoding.ASCII.GetBytes("user").CopyTo(response, 36);
        var session = new FakeSession(response);
        var sink = new FakeSink();
        await new MySqlAdapter().HandleAsync(session, Context("mysql"), Profile("mysql"), sink);
        Assert.True(session.Writes[0].Length > 20);
        Assert.DoesNotContain(sink.Events, x => x.EventType == "AuthenticationAttempted");
        Assert.Contains(sink.Events, x => x.EventType == "ProtocolViolation");
        Assert.Equal(0, sink.StoredCount);
    }

    [Fact]
    public async Task MysqlUsesRealisticDefaultServerVersion()
    {
        var response = new byte[64];
        Encoding.ASCII.GetBytes("user").CopyTo(response, 36);
        var session = new FakeSession(response);
        await new MySqlAdapter().HandleAsync(session, Context("mysql"), new ServiceProfile
        {
            ProfileId = "profile-default-mysql",
            AdapterKey = "mysql",
        }, new FakeSink());

        Assert.Contains("8.0.36-MySQL Community Server", Encoding.ASCII.GetString(session.Writes[0]), StringComparison.Ordinal);
    }

    [Fact]
    public async Task MongoReturnsHelloResponse()
    {
        var request = MongoHello();
        var session = new FakeSession(request);
        var sink = new FakeSink();
        await new MongoAdapter().HandleAsync(session, Context("mongodb"), Profile("mongodb"), sink);
        Assert.Contains(session.Writes, x => x.Length > 20 && BitConverter.ToInt32(x, 12) == 2013);
        Assert.Contains(sink.Events, x => x.EventType == "HandshakeReceived");
    }

    [Fact]
    public async Task MongoHelloIncludesRealisticHostName()
    {
        var request = MongoHello();
        var session = new FakeSession(request);
        await new MongoAdapter().HandleAsync(session, Context("mongodb"), new ServiceProfile
        {
            ProfileId = "profile-default-mongodb",
            AdapterKey = "mongodb",
        }, new FakeSink());

        Assert.Contains("mongo-db-01", Encoding.UTF8.GetString(session.Writes[0]), StringComparison.Ordinal);
    }

    private static ProtocolSessionContext Context(string adapter) => new(
        "conn-test", "listener-test", "instance-test", adapter, "profile-test",
        new IPEndPoint(IPAddress.Parse("192.0.2.10"), 50000),
        new IPEndPoint(IPAddress.Loopback, 3306), DateTimeOffset.UtcNow);

    private static byte[] MongoHello()
    {
        // 合法 OP_MSG：header、flagBits、kind=0、完整 BSON 文档。
        var document = new BsonDocument { { "hello", 1 }, { "$db", "admin" } }.ToBson();
        var packet = new byte[21 + document.Length];
        BitConverter.GetBytes(packet.Length).CopyTo(packet, 0);
        BitConverter.GetBytes(7).CopyTo(packet, 4);
        BitConverter.GetBytes(2013).CopyTo(packet, 12);
        document.CopyTo(packet, 21);
        return packet;
    }

    private static ServiceProfile Profile(string adapter) => new()
    {
        ProfileId = "profile-test",
        AdapterKey = adapter,
        AdvertisedProduct = adapter,
        AdvertisedVersion = "1.0",
        CredentialEvidenceEncryptionKeyRef = "test-key",
    };

    private sealed class FakeSession : IHoneypotSession
    {
        private readonly byte[] _input;
        private int _offset;
        public FakeSession(byte[] input) => _input = input;
        public string ConnectionId => "conn-test";
        public EndPoint RemoteEndPoint => new IPEndPoint(IPAddress.Parse("192.0.2.10"), 50000);
        public EndPoint LocalEndPoint => new IPEndPoint(IPAddress.Loopback, 3306);
        public string Transport => "tcp";
        public bool IsClosed { get; private set; }
        public List<byte[]> Writes { get; } = new();
        public ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken)
        {
            if (_offset >= _input.Length) return ValueTask.FromResult(0);
            var count = Math.Min(buffer.Length, _input.Length - _offset);
            _input.AsMemory(_offset, count).CopyTo(buffer);
            _offset += count;
            return ValueTask.FromResult(count);
        }
        public ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken) { Writes.Add(buffer.ToArray()); return ValueTask.CompletedTask; }
        public ValueTask CloseAsync(SessionCloseReason reason, CancellationToken cancellationToken = default) { IsClosed = true; return ValueTask.CompletedTask; }
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    private sealed class FakeSink : IInteractionEventSink, ICredentialEvidenceSink
    {
        public List<InteractionEvent> Events { get; } = new();
        public int StoredCount { get; private set; }
        public ValueTask<EventAppendResult> AppendAsync(InteractionEvent interactionEvent, CancellationToken cancellationToken = default) { Events.Add(interactionEvent); return ValueTask.FromResult(EventAppendResult.Accepted()); }
        public ValueTask<string> StoreAsync(CredentialEvidence evidence, CancellationToken cancellationToken = default) { StoredCount++; return ValueTask.FromResult("cred-test"); }
    }
}
