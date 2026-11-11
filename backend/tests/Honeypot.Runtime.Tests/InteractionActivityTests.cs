using System.Net;
using System.Text.Json;
using Honeypot.Api.Common;
using Honeypot.Api.Service;
using Honeypot.Api.Service.impl;
using Honeypot.Engine.Service.impl;
using Honeypot.Protocol.Abstractions.Models;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Xunit;

namespace Honeypot.Runtime.Tests;

public sealed class InteractionActivityTests
{
    [Fact]
    public void NfsAccessDenialIsVisibleWithoutInventingPasswordAttempts()
    {
        var denial = Step("AuthorizationDenied", 2) with { AdapterKey = "nfs", AuthenticationMethod = "AUTH_SYS", RiskDelta = 2 };
        var events = new[] { Step("ConnectionAccepted", 1), denial, Step("SessionClosed", 3) };
        Assert.Equal("AuthorizationDenied", Assert.Single(InteractionActivityProjection.Build(events)).EventType);
        var threats = new InMemoryThreatProfileStore();
        var threat = threats.Apply(denial);
        Assert.Equal(0, threat.AuthenticationAttemptCount);
        Assert.True(threat.CurrentScore > 0);
        Assert.False(OverviewActivityProjection.IsAuthenticationFailure(denial));
    }

    [Fact]
    public void EightConnectionStepsBecomeOneAuthenticationWithoutLosingMetadata()
    {
        var events = LoginSteps();
        var activity = Assert.Single(InteractionActivityProjection.Build(events));
        Assert.Equal(8, activity.EventCount);
        Assert.Equal("AuthenticationAttempted", activity.EventType);
        Assert.Equal("test-user", activity.Username);
        Assert.Equal("TEST", activity.Domain);
        Assert.Equal("CredSSP/NTLM", activity.AuthenticationMethod);
        Assert.Equal("STATUS_LOGON_FAILURE", activity.AuthenticationFailureCode);
        Assert.Equal("Response", activity.MaterialType);
        Assert.Equal("cred-isolated", activity.CredentialArtifactId);
        Assert.DoesNotContain("never-expose-this-test-password", JsonSerializer.Serialize(activity));
    }

    [Fact]
    public void SeparatePasswordSubmissionsAndConnectionsAreNeverMerged()
    {
        var events = LoginSteps();
        var second = events[6] with { EventId = "second-auth", Sequence = 8, AuthenticationAttempt = 2 };
        var third = events[6] with { EventId = "other-connection", ConnectionId = "conn-other" };
        var activities = InteractionActivityProjection.Build(events.Concat(new[] { second, third }));
        Assert.Equal(3, activities.Count);
        Assert.Equal(2, activities.Count(item => item.ConnectionId == "conn"));
        Assert.Equal(1, activities.Count(item => item.ConnectionId == "conn-other"));
    }

    [Fact]
    public void FailedHandshakeRetainsOneDiagnosticAndSimpleScanRetainsOneConnection()
    {
        var failed = LoginSteps().Where(item => item.EventType != "AuthenticationAttempted").ToList();
        failed.Insert(5, Step("ProtocolViolation", 6));
        var activity = Assert.Single(InteractionActivityProjection.Build(failed));
        Assert.Equal("ProtocolViolation", activity.EventType);
        Assert.Equal(8, activity.EventCount);
        Assert.Null(activity.Username);
        var scan = Assert.Single(InteractionActivityProjection.Build(new[] { Step("ConnectionAccepted", 1), Step("SessionClosed", 2) }));
        Assert.Equal("ConnectionAccepted", scan.EventType);
        Assert.Equal(2, scan.EventCount);
    }

    [Theory]
    [InlineData("ResourceLimitExceeded")]
    [InlineData("HandshakeTimeout")]
    [InlineData("AuthenticationRequired")]
    [InlineData("CredentialCaptureFailed")]
    [InlineData("AuthenticationEventWriteFailed")]
    public void RecordingAndResourceFailuresStayVisible(string eventType)
    {
        var activity = Assert.Single(InteractionActivityProjection.Build(new[]
        {
            Step("ConnectionAccepted", 1), Step(eventType, 2), Step("SessionClosed", 3),
        }));
        Assert.Equal(eventType, activity.EventType);
    }

    [Fact]
    public async Task HttpActivityViewFiltersAfterGroupingAndPreservesRawConnectionDetails()
    {
        using var evidence = new InMemoryCredentialEvidenceStore();
        var store = new InMemoryInteractionEventStore(new InMemoryThreatProfileStore(), evidence);
        foreach (var item in LoginSteps()) await store.AppendAsync(item);
        var builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        builder.Logging.ClearProviders();
        builder.Services.AddSingleton<IInteractionEventStore>(store);
        await using var app = builder.Build();
        // 仅验证查询合同，不启动主应用、不触碰 SQLite 和真实登录会话。
        app.MapInteractionEventEndpoints();
        await app.StartAsync();
        try
        {
            using var client = new HttpClient { BaseAddress = new Uri(Assert.Single(app.Urls)) };
            var body = await client.GetStringAsync("/api/v1/events?view=activity&sourceIp=192.0.2.10&adapterKey=rdp&destinationPort=3389");
            using var activity = JsonDocument.Parse(body);
            Assert.Equal(1, activity.RootElement.GetProperty("data").GetProperty("total").GetInt32());
            Assert.Equal(8, activity.RootElement.GetProperty("data").GetProperty("items")[0].GetProperty("eventCount").GetInt32());
            Assert.DoesNotContain("never-expose-this-test-password", body);

            using var hidden = JsonDocument.Parse(await client.GetStringAsync("/api/v1/events?view=activity&eventType=ConnectionAccepted"));
            Assert.Equal(0, hidden.RootElement.GetProperty("data").GetProperty("total").GetInt32());
            using var wrongPort = JsonDocument.Parse(await client.GetStringAsync("/api/v1/events?view=activity&destinationPort=9999"));
            Assert.Equal(0, wrongPort.RootElement.GetProperty("data").GetProperty("total").GetInt32());
            using var raw = JsonDocument.Parse(await client.GetStringAsync("/api/v1/events"));
            Assert.Equal(8, raw.RootElement.GetProperty("data").GetProperty("total").GetInt32());
            var details = await client.GetStringAsync("/api/v1/connections/conn/events");
            using var connection = JsonDocument.Parse(details);
            Assert.Equal(8, connection.RootElement.GetProperty("data").GetArrayLength());
            Assert.DoesNotContain("never-expose-this-test-password", details);
            Assert.Equal(HttpStatusCode.BadRequest, (await client.GetAsync("/api/v1/events?view=unsupported")).StatusCode);
        }
        finally { await app.StopAsync(); }
    }

    private static InteractionEvent[] LoginSteps() => new[]
    {
        Step("ConnectionAccepted", 1), Step("HandshakeReceived", 2), Step("NegotiationResponseSent", 3),
        Step("TlsHandshakeCompleted", 4), Step("CredSspChallengeSent", 5), Step("HandshakeReceived", 6),
        Step("AuthenticationAttempted", 7) with { Username = "test-user", Domain = "TEST", AuthenticationMethod = "CredSSP/NTLM",
            AuthenticationFailureCode = "STATUS_LOGON_FAILURE", AuthenticationAttempt = 1, CredentialArtifactId = "cred-isolated",
            MaterialType = "Response", CredentialCaptureStatus = "Captured", Password = "never-expose-this-test-password" },
        Step("SessionClosed", 8),
    };

    private static InteractionEvent Step(string type, long sequence) => new()
    {
        EventId = $"evt-{sequence}-{type}", ConnectionId = "conn", Sequence = sequence, EventType = type,
        OccurredAtUtc = new DateTimeOffset(2026, 11, 9, 0, 0, 0, TimeSpan.Zero).AddMilliseconds(sequence),
        SourceIp = "192.0.2.10", DestinationIp = "127.0.0.1", DestinationPort = 3389,
        ListenerId = "listener", ServiceInstanceId = "instance", AdapterKey = "rdp", ProfileId = "profile", Outcome = "failure",
    };
}
