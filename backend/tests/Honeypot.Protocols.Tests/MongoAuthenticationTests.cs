using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using Honeypot.Protocols.Mongo;
using MongoDB.Bson;
using MongoDB.Bson.Serialization;
using MongoDB.Driver;
using Xunit;

namespace Honeypot.Protocols.Tests;

public sealed class MongoAuthenticationTests
{
    [Theory]
    [InlineData("SCRAM-SHA-1")]
    [InlineData("SCRAM-SHA-256")]
    public async Task OfficialDriverSendsClientProofAndReceivesCode18(string mechanism)
    {
        await using var server = new AuthenticationTestServer(new MongoAdapter(), AuthenticationTestServer.Profile("mongodb"));
        var settings = MongoClientSettings.FromUrl(new MongoUrlBuilder
        {
            Server = new MongoServerAddress("127.0.0.1", server.Port), DirectConnection = true,
            Username = "isolated-user", Password = "isolated-password", AuthenticationSource = "admin", AuthenticationMechanism = mechanism,
            ServerSelectionTimeout = TimeSpan.FromSeconds(5), ConnectTimeout = TimeSpan.FromSeconds(5),
            MaxConnectionPoolSize = 1, RetryReads = false, RetryWrites = false,
        }.ToMongoUrl());
        using var client = new MongoClient(settings);
        var error = await Assert.ThrowsAsync<MongoAuthenticationException>(() => client.GetDatabase("admin").RunCommandAsync<BsonDocument>(new BsonDocument("ping", 1)));
        var commandError = Assert.IsType<MongoCommandException>(error.InnerException);
        Assert.True(commandError.Code == 18, commandError.Message);
        var authentication = await server.Sink.Authentication.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal("isolated-user", authentication.Username);
        Assert.Equal("admin", authentication.Database);
        Assert.Equal(mechanism, authentication.AuthenticationMethod);
        Assert.Equal("Response", authentication.MaterialType);
        Assert.Equal("18", authentication.AuthenticationFailureCode);
        var evidence = server.Sink.Evidence.Single(x => x.EventId == authentication.EventId);
        using var json = JsonDocument.Parse(evidence.Content);
        Assert.Equal("client-proof", json.RootElement.GetProperty("stage").GetString());
        var final = Encoding.UTF8.GetString(Convert.FromBase64String(json.RootElement.GetProperty("clientFinal").GetString()!));
        Assert.Contains(",p=", final, StringComparison.Ordinal);
        Assert.False(json.RootElement.TryGetProperty("password", out _));
        Assert.DoesNotContain("isolated-password", Encoding.UTF8.GetString(evidence.Content.Span), StringComparison.Ordinal);
        Assert.Null(authentication.Password);
        Assert.Empty(server.Errors);
    }

    [Theory]
    [InlineData("密码样本", "用户,=名")]
    [InlineData("", "")]
    public async Task ExplicitPlainCapturesExactPasswordAndReturns18(string password, string username)
    {
        var auth = new BsonDocument
        {
            { "saslStart", 1 }, { "mechanism", "PLAIN" },
            { "payload", new BsonBinaryData(Encoding.UTF8.GetBytes("\0" + username + "\0" + password)) }, { "$db", "$external" },
        };
        var session = new AuthenticationByteSession(Packet(auth), 1);
        var sink = new AuthenticationRecordingSink();
        await new MongoAdapter().HandleAsync(session, AuthenticationTestServer.Context("mongodb"), AuthenticationTestServer.Profile("mongodb"), sink);
        var reply = Decode(Assert.Single(session.Writes));
        Assert.Equal(18, reply["code"].AsInt32);
        var authentication = Assert.Single(sink.Events, x => x.EventType == "AuthenticationAttempted");
        Assert.Equal(username, authentication.Username);
        Assert.Equal("Plaintext", authentication.MaterialType);
        using var json = JsonDocument.Parse(Assert.Single(sink.Evidence).Content);
        Assert.Equal(password, json.RootElement.GetProperty("password").GetString());
        Assert.True(session.IsClosed);
    }

    [Fact]
    public async Task LegacyQueryHelloReturnsOpReplyWithoutAuthentication()
    {
        var document = new BsonDocument { { "ismaster", 1 }, { "helloOk", true }, { "saslSupportedMechs", "admin.user" } };
        var bson = document.ToBson(); var name = Encoding.ASCII.GetBytes("admin.$cmd\0");
        var packet = new byte[16 + 4 + name.Length + 8 + bson.Length];
        BinaryPrimitives.WriteInt32LittleEndian(packet, packet.Length);
        BinaryPrimitives.WriteInt32LittleEndian(packet.AsSpan(4), 7);
        BinaryPrimitives.WriteInt32LittleEndian(packet.AsSpan(12), 2004);
        name.CopyTo(packet, 20);
        BinaryPrimitives.WriteInt32LittleEndian(packet.AsSpan(20 + name.Length + 4), -1);
        bson.CopyTo(packet, 20 + name.Length + 8);
        var session = new AuthenticationByteSession(packet, 3); var sink = new AuthenticationRecordingSink();
        await new MongoAdapter().HandleAsync(session, AuthenticationTestServer.Context("mongodb"), AuthenticationTestServer.Profile("mongodb"), sink);
        var output = Assert.Single(session.Writes);
        Assert.Equal(1, BinaryPrimitives.ReadInt32LittleEndian(output.AsSpan(12)));
        Assert.Equal(7, BinaryPrimitives.ReadInt32LittleEndian(output.AsSpan(8)));
        var hello = BsonSerializer.Deserialize<BsonDocument>(output.AsSpan(36).ToArray());
        Assert.Equal(1.0, hello["ok"].AsDouble);
        Assert.Contains("SCRAM-SHA-256", hello["saslSupportedMechs"].AsBsonArray.Select(x => x.AsString));
        Assert.DoesNotContain(sink.Events, x => x.EventType == "AuthenticationAttempted");
        Assert.Empty(sink.Evidence);
    }

    [Fact]
    public async Task SpeculativeScramKeepsHelloSuccessfulAndChallengesInsideNestedDocument()
    {
        var start = new BsonDocument
        {
            { "saslStart", 1 }, { "mechanism", "SCRAM-SHA-256" },
            { "payload", new BsonBinaryData(Encoding.UTF8.GetBytes("n,,n=user=2C=3D,r=clientnonce")) }, { "db", "admin" },
        };
        var hello = new BsonDocument { { "hello", 1 }, { "saslSupportedMechs", "admin.user" }, { "speculativeAuthenticate", start } };
        var session = new AuthenticationByteSession(Packet(hello)); var sink = new AuthenticationRecordingSink();
        await new MongoAdapter().HandleAsync(session, AuthenticationTestServer.Context("mongodb"), AuthenticationTestServer.Profile("mongodb"), sink);
        var reply = Decode(Assert.Single(session.Writes));
        Assert.Equal(1.0, reply["ok"].AsDouble);
        var nested = reply["speculativeAuthenticate"].AsBsonDocument;
        Assert.False(nested["done"].AsBoolean);
        Assert.StartsWith("r=clientnonce", Encoding.UTF8.GetString(nested["payload"].AsBsonBinaryData.Bytes), StringComparison.Ordinal);
        Assert.Equal("user,=", Assert.Single(sink.Events, x => x.EventType == "AuthenticationAttempted").Username);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task InvalidNonceOrConversationStillFailsAndRecordsSubmittedProof(bool wrongNonce)
    {
        await using var server = new AuthenticationTestServer(new MongoAdapter(), AuthenticationTestServer.Profile("mongodb"));
        using var client = new TcpClient(); await client.ConnectAsync(IPAddress.Loopback, server.Port);
        var stream = client.GetStream();
        var start = new BsonDocument
        {
            { "saslStart", 1 }, { "mechanism", "SCRAM-SHA-256" },
            { "payload", new BsonBinaryData(Encoding.UTF8.GetBytes("n,,n=user,r=nonce")) }, { "$db", "admin" },
        };
        var challenge = await ExchangeAsync(stream, start);
        var serverFirst = Encoding.UTF8.GetString(challenge["payload"].AsBsonBinaryData.Bytes);
        var nonce = serverFirst.Split(',')[0][2..];
        var final = $"c=biws,r={(wrongNonce ? "bad-nonce" : nonce)},p={Convert.ToBase64String(new byte[32])}";
        var continuation = new BsonDocument
        {
            { "saslContinue", 1 }, { "conversationId", challenge["conversationId"].AsInt32 + (wrongNonce ? 0 : 1) },
            { "payload", new BsonBinaryData(Encoding.UTF8.GetBytes(final)) }, { "$db", "admin" },
        };
        Assert.Equal(18, (await ExchangeAsync(stream, continuation))["code"].AsInt32);
        var evidence = Assert.Single(server.Sink.Evidence);
        using var json = JsonDocument.Parse(evidence.Content);
        Assert.Equal("invalid-client-final", json.RootElement.GetProperty("stage").GetString());
        Assert.Equal(final, Encoding.UTF8.GetString(Convert.FromBase64String(json.RootElement.GetProperty("clientFinal").GetString()!)));
    }

    [Fact]
    public async Task MalformedBsonCannotBecomeAuthentication()
    {
        var packet = Packet(new BsonDocument("hello", 1));
        BinaryPrimitives.WriteInt32LittleEndian(packet.AsSpan(21), int.MaxValue);
        var session = new AuthenticationByteSession(packet); var sink = new AuthenticationRecordingSink();
        await new MongoAdapter().HandleAsync(session, AuthenticationTestServer.Context("mongodb"), AuthenticationTestServer.Profile("mongodb"), sink);
        Assert.Empty(session.Writes);
        Assert.Empty(sink.Evidence);
        Assert.Contains(sink.Events, x => x.EventType == "ProtocolViolation");
        Assert.True(session.IsClosed);
    }

    [Fact]
    public async Task UnsupportedMechanismIsCapturedAndRejectedWithoutCredentialFallback()
    {
        var request = new BsonDocument { { "saslStart", 1 }, { "mechanism", "UNSUPPORTED" }, { "payload", new BsonBinaryData(new byte[] { 1, 2, 3 }) }, { "$db", "admin" } };
        var session = new AuthenticationByteSession(Packet(request)); var sink = new AuthenticationRecordingSink();
        await new MongoAdapter().HandleAsync(session, AuthenticationTestServer.Context("mongodb"), AuthenticationTestServer.Profile("mongodb"), sink);
        Assert.Equal(18, Decode(Assert.Single(session.Writes))["code"].AsInt32);
        Assert.Equal("Response", Assert.Single(sink.Evidence).MaterialType);
        Assert.Equal("UNSUPPORTED", Assert.Single(sink.Events, x => x.EventType == "AuthenticationAttempted").AuthenticationMethod);
    }

    [Theory]
    [InlineData("PLAIN", "broken-password-field")]
    [InlineData("SCRAM-SHA-256", "n,,n=user,r=")]
    public async Task MalformedAuthenticationPayloadIsCapturedWithoutPretendingItIsPassword(string mechanism, string payload)
    {
        var request = new BsonDocument
        {
            { "saslStart", 1 }, { "mechanism", mechanism }, { "payload", new BsonBinaryData(Encoding.UTF8.GetBytes(payload)) }, { "$db", "admin" },
        };
        var session = new AuthenticationByteSession(Packet(request)); var sink = new AuthenticationRecordingSink();
        await new MongoAdapter().HandleAsync(session, AuthenticationTestServer.Context("mongodb"), AuthenticationTestServer.Profile("mongodb"), sink);
        Assert.Equal(18, Decode(Assert.Single(session.Writes))["code"].AsInt32);
        var evidence = Assert.Single(sink.Evidence);
        Assert.Equal("Response", evidence.MaterialType);
        using var json = JsonDocument.Parse(evidence.Content);
        Assert.Equal("malformed-authentication", json.RootElement.GetProperty("stage").GetString());
        Assert.False(json.RootElement.TryGetProperty("password", out _));
    }

    [Fact]
    public async Task ScramTimeoutKeepsClientFirstWithoutClaimingToHaveProof()
    {
        var request = new BsonDocument
        {
            { "saslStart", 1 }, { "mechanism", "SCRAM-SHA-256" },
            { "payload", new BsonBinaryData(Encoding.UTF8.GetBytes("n,,n=user,r=nonce")) }, { "$db", "admin" },
        };
        var session = new AuthenticationByteSession(Packet(request), waitWhenExhausted: true); var sink = new AuthenticationRecordingSink();
        await new MongoAdapter().HandleAsync(session, AuthenticationTestServer.Context("mongodb"),
            AuthenticationTestServer.Profile("mongodb") with { HandshakeTimeout = TimeSpan.FromMilliseconds(100) }, sink);
        var evidence = Assert.Single(sink.Evidence);
        using var json = JsonDocument.Parse(evidence.Content);
        Assert.Equal("timeout-before-proof", json.RootElement.GetProperty("stage").GetString());
        Assert.Equal(JsonValueKind.Null, json.RootElement.GetProperty("clientFinal").ValueKind);
        Assert.Equal("user", Assert.Single(sink.Events, x => x.EventType == "AuthenticationAttempted").Username);
    }

    private static byte[] Packet(BsonDocument document)
    {
        var bson = document.ToBson(); var packet = new byte[21 + bson.Length];
        BinaryPrimitives.WriteInt32LittleEndian(packet, packet.Length);
        BinaryPrimitives.WriteInt32LittleEndian(packet.AsSpan(4), 17);
        BinaryPrimitives.WriteInt32LittleEndian(packet.AsSpan(12), 2013);
        bson.CopyTo(packet, 21); return packet;
    }
    private static BsonDocument Decode(byte[] packet) => BsonSerializer.Deserialize<BsonDocument>(packet.AsSpan(21).ToArray());
    private static async Task<BsonDocument> ExchangeAsync(NetworkStream stream, BsonDocument document)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        await stream.WriteAsync(Packet(document), timeout.Token);
        var header = new byte[4]; await stream.ReadExactlyAsync(header, timeout.Token);
        var packet = new byte[BinaryPrimitives.ReadInt32LittleEndian(header)]; header.CopyTo(packet, 0);
        await stream.ReadExactlyAsync(packet.AsMemory(4), timeout.Token); return Decode(packet);
    }
}
