using System.Buffers.Binary;
using System.Text;
using System.Text.Json;
using Honeypot.Protocols.PostgreSql;
using Npgsql;
using Xunit;

namespace Honeypot.Protocols.Tests;

public sealed class PostgreSqlAuthenticationTests
{
    [Theory]
    [InlineData("scram-sha-256", false)]
    [InlineData("scram-sha-256", true)]
    [InlineData("password", false)]
    [InlineData("password", true)]
    [InlineData("md5", false)]
    [InlineData("md5", true)]
    public async Task RealNpgsqlReceivesInvalidPasswordAndCapturesOnlyActualMaterial(string method, bool tls)
    {
        var profile = AuthenticationTestServer.Profile("postgresql") with { PostgreSqlAuthenticationMethod = method };
        await using var server = new AuthenticationTestServer(new PostgreSqlAdapter(), profile);
        var options = new NpgsqlConnectionStringBuilder
        {
            Host = "127.0.0.1", Port = server.Port, Username = "隔离用户", Password = "isolated-password-雪",
            Database = "isolated_database", Pooling = false, Timeout = 5, SslMode = tls ? SslMode.Require : SslMode.Disable,
        };
        await using var connection = new NpgsqlConnection(options.ConnectionString);
        var exception = await Assert.ThrowsAsync<PostgresException>(() => connection.OpenAsync());
        Assert.Equal("28P01", exception.SqlState);
        Assert.Contains("password authentication failed", exception.Message, StringComparison.Ordinal);
        var authentication = await server.Sink.Authentication.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal("隔离用户", authentication.Username);
        Assert.Equal("isolated_database", authentication.Database);
        Assert.Equal(method, authentication.AuthenticationMethod);
        var evidence = Assert.Single(server.Sink.Evidence, item => item.EventId == authentication.EventId);
        Assert.Equal(authentication.EventId, evidence.EventId);
        using var json = JsonDocument.Parse(evidence.Content);
        if (method == "password")
        {
            Assert.Equal("Plaintext", authentication.MaterialType);
            Assert.Equal("isolated-password-雪", json.RootElement.GetProperty("password").GetString());
        }
        else
        {
            Assert.Equal("Response", authentication.MaterialType);
            Assert.Equal(JsonValueKind.Null, json.RootElement.GetProperty("password").ValueKind);
        }
        Assert.DoesNotContain("isolated-password", JsonSerializer.Serialize(server.Sink.Events), StringComparison.Ordinal);
        // Npgsql 10 默认 GSS Prefer 会另开连接重试；每次实际提交只写一条，不能按 IP 合并丢证据。
        var authentications = server.Sink.Events.Where(x => x.EventType == "AuthenticationAttempted").ToArray();
        Assert.All(authentications.GroupBy(x => x.ConnectionId), group => Assert.Single(group));
        Assert.Equal(authentications.Length, server.Sink.Evidence.Count);
        Assert.Empty(server.Errors);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(4096)]
    public async Task FragmentedEmptyPasswordRemainsEmpty(int fragment)
    {
        var bytes = Join(Startup("user", "database"), Message((byte)'p', [0]));
        var session = new AuthenticationByteSession(bytes, fragment);
        var sink = new AuthenticationRecordingSink();
        await new PostgreSqlAdapter().HandleAsync(session, AuthenticationTestServer.Context("postgresql"),
            AuthenticationTestServer.Profile("postgresql") with { PostgreSqlAuthenticationMethod = "password" }, sink);
        var authentication = Assert.Single(sink.Events, x => x.EventType == "AuthenticationAttempted");
        Assert.Equal("28P01", authentication.AuthenticationFailureCode);
        using var json = JsonDocument.Parse(Assert.Single(sink.Evidence).Content);
        Assert.Equal("", json.RootElement.GetProperty("password").GetString());
        Assert.Contains(session.Writes, x => x[0] == 'E');
        Assert.True(session.IsClosed);
    }

    [Fact]
    public async Task OversizedStartupIsNotAuthentication()
    {
        var session = new AuthenticationByteSession(new byte[] { 0x7f, 0xff, 0xff, 0xff }, 1);
        var sink = new AuthenticationRecordingSink();
        await new PostgreSqlAdapter().HandleAsync(session, AuthenticationTestServer.Context("postgresql"), AuthenticationTestServer.Profile("postgresql"), sink);
        Assert.Empty(sink.Evidence);
        Assert.Contains(sink.Events, x => x.EventType == "ProtocolViolation");
    }

    [Fact]
    public async Task UnavailableEvidenceStoreDoesNotPretendPasswordWasRejectedNormally()
    {
        var session = new AuthenticationByteSession(Join(Startup("user", "database"), Message((byte)'p', "isolated-password\0"u8.ToArray())));
        var sink = new AuthenticationRecordingSink(failStorage: true);
        await new PostgreSqlAdapter().HandleAsync(session, AuthenticationTestServer.Context("postgresql"),
            AuthenticationTestServer.Profile("postgresql") with { PostgreSqlAuthenticationMethod = "password" }, sink);
        Assert.Empty(sink.Evidence);
        Assert.Contains(sink.Events, x => x.EventType == "CredentialCaptureFailed");
        Assert.DoesNotContain(sink.Events, x => x.EventType == "AuthenticationAttempted");
        Assert.DoesNotContain(session.Writes, x => x[0] == 'E');
    }

    private static byte[] Startup(string user, string database)
    {
        var payload = Encoding.UTF8.GetBytes($"user\0{user}\0database\0{database}\0\0");
        var bytes = new byte[payload.Length + 8];
        BinaryPrimitives.WriteInt32BigEndian(bytes, bytes.Length);
        BinaryPrimitives.WriteInt32BigEndian(bytes.AsSpan(4), 196608);
        payload.CopyTo(bytes, 8); return bytes;
    }
    private static byte[] Message(byte type, byte[] body)
    {
        var bytes = new byte[body.Length + 5]; bytes[0] = type;
        BinaryPrimitives.WriteInt32BigEndian(bytes.AsSpan(1), body.Length + 4); body.CopyTo(bytes, 5); return bytes;
    }
    private static byte[] Join(params byte[][] chunks) => chunks.SelectMany(x => x).ToArray();
}
