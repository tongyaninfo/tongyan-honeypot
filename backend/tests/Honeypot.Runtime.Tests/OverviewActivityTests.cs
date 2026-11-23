using System.Net;
using System.Text.Json;
using Honeypot.Api.Common;
using Honeypot.Api.Models;
using Honeypot.Api.Service;
using Honeypot.Api.Service.impl;
using Honeypot.Engine.Service;
using Honeypot.Engine.Service.impl;
using Honeypot.Protocol.Abstractions.Models;
using Honeypot.Protocol.Abstractions.Service;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
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
        Assert.All(hours[1..^1], hour => Assert.Equal(((long?)0, (long?)0), (hour.AcceptedConnections, hour.AuthenticationFailures)));
    }

    [Fact]
    public async Task HttpOverviewConnectionsScopesFilterBeforePagination()
    {
        var midnightInShanghai = new DateTimeOffset(2026, 11, 14, 16, 0, 0, TimeSpan.Zero);
        var clock = new FixedClock(midnightInShanghai.AddHours(12));
        const string source = "192.0.2.10";
        var newest = Event("ConnectionAccepted", midnightInShanghai, source: source) with { EventId = "accepted-a" };
        var sameTime = Event("ConnectionAccepted", midnightInShanghai, source: "192.0.2.20") with
        {
            EventId = "accepted-b", Username = "unexpected-username", CredentialArtifactId = "unexpected-artifact", MaterialType = "Response",
        };
        var older = Event("ConnectionAccepted", midnightInShanghai.AddHours(-2), adapter: " RDP ", source: source);
        var withoutThreat = Event("ConnectionAccepted", midnightInShanghai.AddHours(-1), source: "192.0.2.30");
        var failure = Event("AuthenticationAttempted", midnightInShanghai, outcome: "FaIlUrE") with
        {
            Username = "fixture-username", Password = "fixture-password", PayloadSummary = "fixture-payload",
            SourcePort = 42000, DestinationPort = 3389, MaterialType = "Plaintext",
        };
        var failureWithoutEvidence = Event("AuthenticationAttempted", midnightInShanghai.AddMinutes(1), outcome: "failure") with
            { Username = "fixture-account-only" };
        var previousDay = Event("AuthenticationAttempted", midnightInShanghai.AddTicks(-1), outcome: "failure");
        var nextDay = Event("AuthenticationAttempted", midnightInShanghai.AddDays(1), outcome: "failure");
        var handshaking = Event("HandshakeReceived", midnightInShanghai.AddMinutes(1), outcome: "failure", source: "192.0.2.40");
        var rejected = Event("AuthenticationAttempted", midnightInShanghai.AddMinutes(2), outcome: "rejected");
        var violation = Event("ProtocolViolation", midnightInShanghai.AddMinutes(2), source: "192.0.2.30") with
        {
            PayloadSummary = "Malformed handshake", CredentialArtifactId = "unexpected-artifact",
        };
        var unknownSource = Event("ProtocolViolation", midnightInShanghai.AddMinutes(3), source: "unknown");
        var otherAdapter = Event("ProtocolViolation", midnightInShanghai, adapter: "ssh");
        var windowEnd = Event("ProtocolViolation", clock.GetUtcNow().AddHours(1));
        var beforeWindow = Event("ProtocolViolation", clock.GetUtcNow().AddHours(-23).AddTicks(-1));

        using var evidence = new InMemoryCredentialEvidenceStore();
        var protectedEvidence = await evidence.SaveAsync(failure.ConnectionId, failure.EventId, failure.SourceIp,
            failure.AdapterKey, "Plaintext", "{\"username\":\"fixture-username\",\"password\":\"fixture-password\"}", 1);
        failure = failure with { CredentialArtifactId = protectedEvidence.CredentialArtifactId };
        var events = new InMemoryInteractionEventStore(new InMemoryThreatProfileStore(), evidence);
        foreach (var item in new[] { sameTime, withoutThreat, older, newest, failure, failureWithoutEvidence, previousDay, nextDay,
                     handshaking, rejected, violation, unknownSource, otherAdapter, windowEnd, beforeWindow })
            await events.AppendAsync(item);

        var threats = new InMemoryThreatProfileStore();
        foreach (var item in new[] { newest, sameTime, handshaking }) threats.Apply(item);

        var builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        builder.Logging.ClearProviders();
        builder.Services.AddSingleton<TimeProvider>(clock);
        builder.Services.AddSingleton<OverviewActiveConnections>();
        builder.Services.AddSingleton<IInteractionEventStore>(events);
        builder.Services.AddSingleton<IThreatProfileStore>(threats);
        builder.Services.AddSingleton<IListenerHost>(new SnapshotListener(new("active-connection", clock.GetUtcNow(), source, 42000, "ssh", 22)));
        await using var app = builder.Build();
        app.Use((context, next) =>
        {
            context.Items["CurrentUser"] = new AuthenticatedUser("fixture-viewer", "fixture-viewer", ["Viewer"]);
            return next(context);
        });
        app.MapOverviewConnectionsEndpoints();
        await app.StartAsync();
        try
        {
            using var client = new HttpClient { BaseAddress = new Uri(Assert.Single(app.Urls)) };
            const string path = "/api/v1/metrics/overview/connections";
            var accepted = await ReadPage($"{path}?scope=accepted&page=2&pageSize=1");
            Assert.Equal(4, accepted.GetProperty("total").GetInt32());
            Assert.Equal(2, accepted.GetProperty("page").GetInt32());
            AssertConnectionRow(accepted.GetProperty("items")[0], "accepted-b");

            var failures = await ReadPage($"{path}?scope=authenticationFailures");
            Assert.Equal(2, failures.GetProperty("total").GetInt32());
            var withoutReference = failures.GetProperty("items")[0];
            Assert.Equal(failureWithoutEvidence.EventId, withoutReference.GetProperty("id").GetString());
            Assert.Equal("fixture-account-only", withoutReference.GetProperty("username").GetString());
            Assert.True(!withoutReference.TryGetProperty("credentialArtifactId", out var missingArtifact) || missingArtifact.ValueKind == JsonValueKind.Null);
            Assert.True(!withoutReference.TryGetProperty("materialType", out var missingMaterial) || missingMaterial.ValueKind == JsonValueKind.Null);

            var row = failures.GetProperty("items")[1];
            Assert.Equal(failure.EventId, row.GetProperty("id").GetString());
            Assert.Equal(failure.ConnectionId, row.GetProperty("connectionId").GetString());
            Assert.Equal(midnightInShanghai, row.GetProperty("occurredAtUtc").GetDateTimeOffset());
            Assert.Equal("rdp", row.GetProperty("adapterKey").GetString());
            Assert.Equal(source, row.GetProperty("sourceIp").GetString());
            Assert.Equal(42000, row.GetProperty("sourcePort").GetInt32());
            Assert.Equal(3389, row.GetProperty("destinationPort").GetInt32());
            Assert.Equal("fixture-username", row.GetProperty("username").GetString());
            Assert.Equal(protectedEvidence.CredentialArtifactId, row.GetProperty("credentialArtifactId").GetString());
            Assert.Equal("Plaintext", row.GetProperty("materialType").GetString());
            Assert.Equal(new[] { "adapterKey", "connectionId", "credentialArtifactId", "destinationPort", "id", "materialType",
                "occurredAtUtc", "sourceIp", "sourcePort", "username" },
                row.EnumerateObject().Select(field => field.Name).Order(StringComparer.Ordinal));

            var threatConnections = await ReadPage($"{path}?scope=threatConnections");
            Assert.Equal(2, threatConnections.GetProperty("total").GetInt32());
            Assert.Collection(threatConnections.GetProperty("items").EnumerateArray(),
                item => AssertConnectionRow(item, "accepted-a"),
                item => AssertConnectionRow(item, "accepted-b"));
            var active = await ReadPage($"{path}?scope=active");
            Assert.Equal(1, active.GetProperty("total").GetInt32());
            AssertConnectionRow(Assert.Single(active.GetProperty("items").EnumerateArray()), "active-connection");

            const string protocolQuery = $"{path}?scope=adapterActivity&adapterKey=RDP";
            var protocolAccepted = await ReadPage($"{protocolQuery}&metric=acceptedConnections&page=4&pageSize=1");
            Assert.Equal(4, protocolAccepted.GetProperty("total").GetInt32());
            AssertConnectionRow(Assert.Single(protocolAccepted.GetProperty("items").EnumerateArray()), older.EventId);

            var protocolFailures = await ReadPage($"{protocolQuery}&metric=authenticationFailures");
            Assert.Equal(3, protocolFailures.GetProperty("total").GetInt32());
            Assert.Equal(protectedEvidence.CredentialArtifactId,
                protocolFailures.GetProperty("items")[1].GetProperty("credentialArtifactId").GetString());
            Assert.Equal(previousDay.EventId, protocolFailures.GetProperty("items")[2].GetProperty("id").GetString());

            var sources = await ReadPage($"{protocolQuery}&metric=sourceIpCount&pageSize=1");
            Assert.Equal(3, sources.GetProperty("total").GetInt32());
            var latestSource = Assert.Single(sources.GetProperty("items").EnumerateArray());
            Assert.Equal(violation.EventId, latestSource.GetProperty("id").GetString());
            Assert.Equal("192.0.2.30", latestSource.GetProperty("sourceIp").GetString());
            Assert.Equal("ProtocolViolation", latestSource.GetProperty("eventType").GetString());
            Assert.False(latestSource.TryGetProperty("credentialArtifactId", out _));

            var violations = await ReadPage($"{protocolQuery}&metric=protocolViolations");
            Assert.Equal(2, violations.GetProperty("total").GetInt32());
            var violationDetail = violations.GetProperty("items")[1];
            Assert.Equal("Malformed handshake", violationDetail.GetProperty("protocolViolationSummary").GetString());
            Assert.False(violationDetail.TryGetProperty("credentialArtifactId", out _));

            using var badScope = await client.GetAsync($"{path}?scope=unsupported");
            Assert.Equal(HttpStatusCode.BadRequest, badScope.StatusCode);
            using var badMetric = await client.GetAsync($"{protocolQuery}&metric=unsupported");
            Assert.Equal(HttpStatusCode.BadRequest, badMetric.StatusCode);

            async Task<JsonElement> ReadPage(string address)
            {
                var body = await client.GetStringAsync(address);
                Assert.DoesNotContain("fixture-password", body);
                Assert.DoesNotContain("fixture-payload", body);
                using var json = JsonDocument.Parse(body);
                Assert.True(json.RootElement.GetProperty("success").GetBoolean());
                return json.RootElement.GetProperty("data").Clone();
            }
        }
        finally { await app.StopAsync(); }
    }

    private static void AssertConnectionRow(JsonElement row, string id)
    {
        Assert.Equal(id, row.GetProperty("id").GetString());
        Assert.Equal(new[] { "adapterKey", "connectionId", "destinationPort", "id", "occurredAtUtc", "sourceIp", "sourcePort" },
            row.EnumerateObject().Select(field => field.Name).Order(StringComparer.Ordinal));
    }

    internal sealed class SnapshotListener(ActiveConnectionSnapshot snapshot) : IListenerHost
    {
        public IReadOnlyCollection<ActiveConnectionSnapshot> Active { get; set; } = [snapshot];
        public IReadOnlyCollection<ListenerRuntimeStatus> GetStatuses() => [];
        public IReadOnlyCollection<ActiveConnectionSnapshot> GetActiveConnections() => Active;
        public Task<ListenerApplyResult> ApplyAsync(ServiceInstance instance, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task StopInstanceAsync(string instanceId, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task StopAsync(CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    private sealed class FixedClock(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
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
