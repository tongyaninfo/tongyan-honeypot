using System.Text;
using System.Text.Json;
using Honeypot.Protocols.Telnet;
using Xunit;

namespace Honeypot.Protocols.Tests;

public sealed class TelnetAuthenticationTests
{
    [Fact]
    public async Task NegotiationBackspaceCrLfAndPasswordsDoNotLeakToTerminalOrEvents()
    {
        var input = new byte[] { 255, 253, 1, 255, 251, 3, 255, 251, 24, 255, 250, 24, 0, 255, 240 }
            .Concat(Encoding.UTF8.GetBytes("隔离用错\b户\r\nisolated-password-雪\r\nuser\r\0\r\n")).ToArray();
        var session = new AuthenticationByteSession(input, 1);
        var sink = new AuthenticationRecordingSink();
        await new TelnetAdapter().HandleAsync(session, AuthenticationTestServer.Context("telnet"), AuthenticationTestServer.Profile("telnet"), sink);
        var events = sink.Events.Where(x => x.EventType == "AuthenticationAttempted").ToArray();
        Assert.Equal(2, events.Length);
        Assert.Equal("隔离用户", events[0].Username);
        Assert.Equal("LOGIN_INCORRECT", events[0].AuthenticationFailureCode);
        using var first = JsonDocument.Parse(sink.Evidence.First().Content);
        using var second = JsonDocument.Parse(sink.Evidence.Last().Content);
        Assert.Equal("isolated-password-雪", first.RootElement.GetProperty("password").GetString());
        Assert.Equal("", second.RootElement.GetProperty("password").GetString());
        var output = Encoding.UTF8.GetString(session.Writes.SelectMany(x => x).ToArray());
        Assert.Contains("Login incorrect", output, StringComparison.Ordinal);
        Assert.DoesNotContain("isolated-password", output, StringComparison.Ordinal);
        Assert.DoesNotContain("isolated-password", JsonSerializer.Serialize(sink.Events), StringComparison.Ordinal);
        Assert.Contains(session.Writes, x => x.SequenceEqual(new byte[] { 255, 254, 24 }));
    }

    [Fact]
    public async Task LongLineAndUnterminatedSubnegotiationAreBounded()
    {
        var profile = AuthenticationTestServer.Profile("telnet") with { MaxFrameBytes = 64 };
        foreach (var data in new[] { Encoding.ASCII.GetBytes(new string('a', 100)), new byte[] { 255, 250, 24 }.Concat(new byte[100]).ToArray() })
        {
            var session = new AuthenticationByteSession(data, 1);
            var sink = new AuthenticationRecordingSink();
            await new TelnetAdapter().HandleAsync(session, AuthenticationTestServer.Context("telnet"), profile, sink);
            Assert.Empty(sink.Evidence);
            Assert.Contains(sink.Events, x => x.EventType == "ProtocolViolation");
            Assert.True(session.IsClosed);
        }
    }
}
