using Honeypot.Api.Common;
using Honeypot.Api.Models;
using Honeypot.Protocol.Abstractions.Models;
using Xunit;

namespace Honeypot.Runtime.Tests;

public sealed class OverviewActivityTests
{
    [Fact]
    public void BusinessActivityCountsConnectionsAndFailuresWithoutCountingHandshakeSteps()
    {
        var now = new DateTimeOffset(2026, 11, 9, 17, 42, 0, TimeSpan.FromHours(8));
        var currentHour = new DateTimeOffset(2026, 11, 9, 9, 0, 0, TimeSpan.Zero);
        var firstHour = currentHour.AddHours(-23);
        var latestActivity = currentHour.AddMinutes(5);

        var (steps, adapters, hours) = OverviewActivityProjection.Build(
        [
            Event("ConnectionAccepted", firstHour.AddTicks(-1)),
            Event("ConnectionAccepted", firstHour),
            Event("ConnectionAccepted", currentHour, adapter: " RDP "),
            Event("AuthenticationAttempted", currentHour.AddMinutes(1), outcome: "failure"),
            Event("AuthenticationAttempted", currentHour.AddMinutes(2), outcome: "completed"),
            Event("ProtocolViolation", currentHour.AddMinutes(3), source: "unknown"),
            Event("ProtocolViolation", currentHour.AddMinutes(4), source: " "),
            Event("ProtocolViolation", latestActivity, source: "192.0.2.20"),
            Event("HandshakeReceived", currentHour.AddMinutes(6), source: "192.0.2.30"),
            Event("HandshakeReceived", currentHour.AddMinutes(7), adapter: "ssh"),
            Event("AuthenticationAttempted", currentHour.AddHours(1), outcome: "failure"),
        ], now);

        Assert.Equal(new AdapterActivityMetric("rdp", 2, 1, 2, 3, latestActivity), Assert.Single(adapters));
        Assert.Equal(24, hours.Length);
        Assert.Equal(new HourlyActivityMetric("2026-11-08T10:00:00Z", 1, 0), hours[0]);
        Assert.Equal(new HourlyActivityMetric("2026-11-09T09:00:00Z", 1, 1), hours[^1]);
        Assert.Equal(new MetricBucket(hours[^1].Key, 8), steps[^1]);
        Assert.All(hours[1..^1], hour => Assert.Equal((0, 0), (hour.AcceptedConnections, hour.AuthenticationFailures)));
    }

    private static InteractionEvent Event(string type, DateTimeOffset at, string adapter = "rdp", string source = "192.0.2.10", string outcome = "recorded") => new()
    {
        EventId = $"{adapter}-{type}-{at.UtcTicks}",
        ConnectionId = "fixture-connection",
        EventType = type,
        OccurredAtUtc = at,
        AdapterKey = adapter,
        SourceIp = source,
        DestinationIp = "192.0.2.100",
        ListenerId = "fixture-listener",
        ServiceInstanceId = "fixture-instance",
        ProfileId = "fixture-profile",
        Outcome = outcome,
    };
}
