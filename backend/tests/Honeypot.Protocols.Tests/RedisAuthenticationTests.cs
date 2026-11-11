using System.Text;
using System.Text.Json;
using Honeypot.Protocols.Redis;
using StackExchange.Redis;
using Xunit;

namespace Honeypot.Protocols.Tests;

public sealed class RedisAuthenticationTests
{
    [Theory]
    [InlineData(RedisProtocol.Resp2)]
    [InlineData(RedisProtocol.Resp3)]
    public async Task RealClientRecognizesWrongPassword(RedisProtocol protocol)
    {
        await using var server = new AuthenticationTestServer(new RedisAdapter(), AuthenticationTestServer.Profile("redis"));
        var configuration = new ConfigurationOptions
        {
            EndPoints = { { "127.0.0.1", server.Port } }, User = "isolated-user", Password = "isolated-password-雪",
            Protocol = protocol, AbortOnConnectFail = true, ConnectRetry = 0, ConnectTimeout = 1500, SyncTimeout = 1500,
        };
        var exception = await Assert.ThrowsAsync<RedisConnectionException>(() => ConnectionMultiplexer.ConnectAsync(configuration));
        Assert.True(exception.Message.Contains("WRONGPASS", StringComparison.Ordinal) ||
                    exception.ToString().Contains("AuthenticationFailure", StringComparison.Ordinal), exception.Message);
        var authentication = await server.Sink.Authentication.Task.WaitAsync(TimeSpan.FromSeconds(3));
        Assert.Equal("isolated-user", authentication.Username);
        Assert.Equal("WRONGPASS", authentication.AuthenticationFailureCode);
        using var json = JsonDocument.Parse(server.Sink.Evidence.First().Content);
        Assert.Equal("isolated-password-雪", json.RootElement.GetProperty("password").GetString());
        Assert.DoesNotContain("isolated-password", JsonSerializer.Serialize(server.Sink.Events), StringComparison.Ordinal);
        Assert.Empty(server.Errors);
    }

    [Theory]
    [InlineData("AUTH \"a user\" \"a password\"\r\n", "a user", "a password")]
    [InlineData("AUTH ''\r\n", "default", "")]
    [InlineData("AUTH 'a\\q' 'p\\q'\r\n", "a\\q", "p\\q")]
    [InlineData("HELLO 3 AUTH test pass SETNAME isolated\r\n", "test", "pass")]
    public async Task InlineQuotedAndEmptyPasswordsAreRecorded(string command, string user, string password)
    {
        var session = new AuthenticationByteSession(Encoding.UTF8.GetBytes(command), 1);
        var sink = new AuthenticationRecordingSink();
        await new RedisAdapter().HandleAsync(session, AuthenticationTestServer.Context("redis"), AuthenticationTestServer.Profile("redis"), sink);
        var authentication = Assert.Single(sink.Events, x => x.EventType == "AuthenticationAttempted");
        Assert.Equal(user, authentication.Username);
        using var json = JsonDocument.Parse(Assert.Single(sink.Evidence).Content);
        Assert.Equal(password, json.RootElement.GetProperty("password").GetString());
        Assert.Contains(session.Writes, x => Encoding.UTF8.GetString(x).StartsWith("-WRONGPASS", StringComparison.Ordinal));
    }

    [Fact]
    public async Task PipelineRetriesAreCountedPerSubmissionAndProbeIsNotAuthentication()
    {
        var session = new AuthenticationByteSession(Encoding.UTF8.GetBytes("PING\r\nAUTH first\r\nAUTH second\r\nQUIT\r\n"), 1);
        var sink = new AuthenticationRecordingSink();
        await new RedisAdapter().HandleAsync(session, AuthenticationTestServer.Context("redis"), AuthenticationTestServer.Profile("redis"), sink);
        Assert.Equal(new int?[] { 1, 2 }, sink.Events.Where(x => x.EventType == "AuthenticationAttempted").Select(x => x.AuthenticationAttempt));
        Assert.Equal(2, sink.Evidence.Count);
        Assert.StartsWith("-NOAUTH", Encoding.UTF8.GetString(session.Writes[0]));
    }

    [Theory]
    [InlineData("*3\r\n$4\r\nAUTH\r\n$5\r\nuser1\r\n$999999999\r\n")]
    [InlineData("*2147483647\r\n")]
    [InlineData("AUTH \"unclosed\r\n")]
    public async Task InvalidFramesNeverBecomeCredentialEvidence(string frame)
    {
        var session = new AuthenticationByteSession(Encoding.UTF8.GetBytes(frame), 1);
        var sink = new AuthenticationRecordingSink();
        await new RedisAdapter().HandleAsync(session, AuthenticationTestServer.Context("redis"), AuthenticationTestServer.Profile("redis"), sink);
        Assert.Empty(sink.Evidence);
        Assert.Contains(sink.Events, x => x.EventType == "ProtocolViolation");
        Assert.True(session.IsClosed);
    }
}
