using System.Net;
using System.Text.Json;
using Honeypot.Api.Common;
using Honeypot.Api.Models;
using Honeypot.Api.Service;
using Honeypot.Api.Service.impl;
using Honeypot.Engine.Service.impl;
using Honeypot.Protocol.Abstractions.Models;
using Honeypot.Shared.Models;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Xunit;

namespace Honeypot.Runtime.Tests;

public sealed class ConnectionMapTests
{
    private const string Route = "/api/v1/metrics/overview/connection-map";
    private static readonly DateTimeOffset Now = new(2026, 11, 15, 4, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task RequiresLoginAndReturnsOnlyDistinctRecentConnectionsWithUsableCoordinates()
    {
        const string ipv4 = "192.0.3.10"; // 仅供模拟定位使用的公网形状地址。
        var oldest = Event("edge", Now.AddSeconds(-60), Source(1), "rdp");
        var newest = Event("fresh", Now, $"::ffff:{ipv4}", "ssh");
        var sameSource = Event("same-source", Now.AddSeconds(-1), ipv4, "postgresql");
        var fixture = new[]
        {
            oldest, newest, newest with { EventId = "duplicated-accept" }, sameSource,
            Event("before-edge", Now.AddSeconds(-60).AddTicks(-1), Source(7)),
            Event("in-future", Now.AddTicks(1), Source(8)),
            Event("auth", Now.AddSeconds(-3), Source(2)) with { EventType = "AuthenticationAttempted" },
            Event("closed", Now.AddSeconds(-4), Source(2)) with { EventType = "SessionClosed" },
            Event("pending", Now.AddSeconds(-5), Source(3)),
            Event("missing-coordinate", Now.AddSeconds(-6), Source(4)),
            Event("invalid-coordinate", Now.AddSeconds(-7), Source(5)),
            Event("busy", Now.AddSeconds(-8), Source(6)),
            Event("deferred", Now.AddSeconds(-9), Source(9)),
            Event("private", Now.AddSeconds(-8), "10.0.0.10"),
            Event("reserved", Now.AddSeconds(-9), "192.0.2.11"),
            Event("malformed", Now.AddSeconds(-10), "invalid-source"),
        };
        var resolver = new StubResolver(ip =>
        {
            if (ip == Source(3)) return new(ip, "pending");
            if (ip == Source(4)) return new(ip, "resolved", Latitude: 10);
            if (ip == Source(5)) return new(ip, "resolved", Latitude: 91, Longitude: double.NaN);
            if (ip == Source(6)) return new(ip, "busy");
            if (ip == Source(9)) return new(ip, "deferred");
            if (ip == ipv4) return Mapped(ip) with { Country = "测试来源国家" };
            return Mapped(ip);
        });
        var target = new StubTarget(new("ready", Source: "detectedPublicIp", Label: "测试目标",
            Latitude: 0, Longitude: 0, UpdatedAtUtc: Now.AddDays(-2), Stale: true));
        await using var app = await StartAppAsync(fixture, resolver, target);
        using var client = new HttpClient { BaseAddress = new Uri(Assert.Single(app.Urls)) };

        using var unauthorized = await client.GetAsync(Route);
        Assert.Equal(HttpStatusCode.Unauthorized, unauthorized.StatusCode);
        var rejectedBody = await unauthorized.Content.ReadAsStringAsync();
        Assert.DoesNotContain("sourceIp", rejectedBody, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(ipv4, rejectedBody);
        Assert.Empty(resolver.Requests);

        client.DefaultRequestHeaders.Add("X-Test-Identity", "viewer");
        var (body, data) = await ReadSnapshotAsync(client, windowSeconds: 60);
        Assert.Equal(Now, data.GetProperty("sampledAtUtc").GetDateTimeOffset());
        Assert.Equal(60, data.GetProperty("windowSeconds").GetInt32());
        Assert.True(data.GetProperty("locationEnabled").GetBoolean());
        var destination = data.GetProperty("target");
        Assert.Equal("ready", destination.GetProperty("status").GetString());
        Assert.Equal("测试目标", destination.GetProperty("label").GetString());
        Assert.Equal(0, destination.GetProperty("longitude").GetDouble());
        Assert.Equal(0, destination.GetProperty("latitude").GetDouble());
        Assert.True(destination.GetProperty("stale").GetBoolean());
        Assert.Equal(Now.AddDays(-2), destination.GetProperty("updatedAtUtc").GetDateTimeOffset());
        Assert.Equal("detectedPublicIp", destination.GetProperty("source").GetString());
        Assert.DoesNotContain(destination.EnumerateObject(), field => field.Name is "sourceIp" or "publicIp");
        Assert.DoesNotContain(data.EnumerateObject(), field => field.Name == "sourceIp");
        Assert.DoesNotContain(data.GetProperty("coverage").EnumerateObject(), field => field.Name == "sourceIp");
        Assert.DoesNotContain($"::ffff:{ipv4}", body, StringComparison.OrdinalIgnoreCase);
        foreach (var ip in Enumerable.Range(2, 8).Select(Source).Concat(["10.0.0.10", "192.0.2.11", "invalid-source"]))
            Assert.DoesNotContain(ip, body);
        Assert.DoesNotContain("isolated-username", body);
        Assert.DoesNotContain("isolated-password", body);
        Assert.DoesNotContain("isolated-credential-id", body);
        Assert.DoesNotContain("isolated-payload", body);
        // IPv4-mapped 与原生 IPv4 共享一次定位，两个不同的接纳连接仍各自进入地图。
        Assert.Equal(new[] { ipv4, Source(1), Source(3), Source(4), Source(5), Source(6), Source(9) },
            resolver.Requests.SelectMany(batch => batch).Order(StringComparer.Ordinal));

        Assert.Collection(data.GetProperty("events").EnumerateArray(),
            item => AssertEvent(item, newest, ipv4, "测试来源国家"),
            item => AssertEvent(item, sameSource, ipv4, "测试来源国家"),
            item => AssertEvent(item, oldest, Source(1), ""));
        var origin = Assert.Single(data.GetProperty("origins").EnumerateArray());
        Assert.Equal(3, origin.GetProperty("connectionCount").GetInt32());
        Assert.Equal(2, origin.GetProperty("sourceIpCount").GetInt32());
        Assert.Equal("ssh", origin.GetProperty("adapterKey").GetString());
        Assert.Collection(origin.GetProperty("sources").EnumerateArray(),
            item => AssertSource(item, ipv4, "测试来源国家"),
            item => AssertSource(item, Source(1), ""));
        Assert.Equal(new[] { "postgresql", "rdp", "ssh" }, data.GetProperty("adapterKeys").EnumerateArray().Select(item => item.GetString()));
        AssertCoverage(data, observed: 11, mapped: 3, unknown: 3, privateCount: 2, pending: 3, omitted: 0, deferred: 2);
    }

    [Theory]
    [InlineData(null, 600)]
    [InlineData(60, 60)]
    [InlineData(600, 600)]
    [InlineData(7200, 7200)]
    [InlineData(86400, 86400)]
    public async Task RequestedOrDefaultWindowIncludesBothEdges(int? requestedWindow, int expectedWindow)
    {
        var start = Now.AddSeconds(-expectedWindow);
        var fixtures = new[]
        {
            Event("oldest", start, Source(1)),
            Event("before-window", start.AddTicks(-1), Source(2)),
            Event("newest", Now, Source(3)),
            Event("after-window", Now.AddTicks(1), Source(4)),
        };
        await using var app = await StartAppAsync(fixtures, new StubResolver(Mapped), new StubTarget(new("unavailable")));
        using var client = new HttpClient { BaseAddress = new Uri(Assert.Single(app.Urls)) };
        client.DefaultRequestHeaders.Add("X-Test-Identity", "viewer");

        var (_, data) = await ReadSnapshotAsync(client, requestedWindow);
        Assert.Equal(expectedWindow, data.GetProperty("windowSeconds").GetInt32());
        Assert.Equal(new[] { "newest", "oldest" }, data.GetProperty("events").EnumerateArray()
            .Select(item => item.GetProperty("id").GetString()));
        AssertCoverage(data, observed: 2, mapped: 2, unknown: 0, privateCount: 0, pending: 0, omitted: 0);
    }

    [Fact]
    public async Task InvalidOrRepeatedWindowReturnsBadRequestWithoutLookingUpLocations()
    {
        var resolver = new StubResolver(Mapped);
        await using var app = await StartAppAsync([Event("current", Now, Source(1))], resolver, new StubTarget(new("unavailable")));
        using var client = new HttpClient { BaseAddress = new Uri(Assert.Single(app.Urls)) };
        client.DefaultRequestHeaders.Add("X-Test-Identity", "viewer");

        foreach (var value in new[] { "", "0", "-60", "120", "86401", "600.0", "invalid", "60&windowSeconds=600" })
        {
            using var response = await client.GetAsync($"{Route}?windowSeconds={value}");
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.True(response.Headers.CacheControl?.NoStore);
            using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            Assert.False(json.RootElement.GetProperty("success").GetBoolean());
            Assert.Equal("INVALID_WINDOW", json.RootElement.GetProperty("code").GetString());
        }
        Assert.Empty(resolver.Requests);
    }

    [Fact]
    public async Task CountsEveryLocatedConnectionWhileReturningOnlyTheNewestHundredFlights()
    {
        var fixtures = Enumerable.Range(1, 1_030)
            .Select(index => Event($"conn-{index:0000}", Now.AddHours(-23).AddMilliseconds(-index), Source(index),
                index == 1_030 ? "mssql" : "ssh"))
            .Reverse().ToArray();
        var resolver = new StubResolver(Mapped);
        await using var app = await StartAppAsync(fixtures, resolver, new StubTarget(new("unavailable")));
        using var client = new HttpClient { BaseAddress = new Uri(Assert.Single(app.Urls)) };
        client.DefaultRequestHeaders.Add("X-Test-Identity", "viewer");

        var (_, data) = await ReadSnapshotAsync(client, windowSeconds: 86400);
        var items = data.GetProperty("events").EnumerateArray().ToArray();
        Assert.Equal(100, items.Length);
        Assert.Equal(1_030, resolver.Requests.SelectMany(batch => batch).Distinct().Count());
        Assert.Equal(Enumerable.Range(1, 100).Select(index => $"conn-{index:0000}"),
            items.Select(item => item.GetProperty("id").GetString()));
        Assert.Equal("unavailable", data.GetProperty("target").GetProperty("status").GetString());
        var origin = Assert.Single(data.GetProperty("origins").EnumerateArray());
        Assert.Equal(1_030, origin.GetProperty("connectionCount").GetInt32());
        Assert.Equal(1_030, origin.GetProperty("sourceIpCount").GetInt32());
        Assert.Equal(Enumerable.Range(1, 12).Select(Source),
            origin.GetProperty("sources").EnumerateArray().Select(item => item.GetProperty("ip").GetString()));
        Assert.Equal(new[] { "mssql", "ssh" }, data.GetProperty("adapterKeys").EnumerateArray().Select(item => item.GetString()));
        AssertCoverage(data, observed: 1_030, mapped: 1_030, unknown: 0, privateCount: 0, pending: 0, omitted: 930);
    }

    [Fact]
    public async Task GridCoarsensBeyondFourHundredPointsAndPreservesCounts()
    {
        var fixtures = Enumerable.Range(1, 501).Select(index =>
                Event($"grid-{index}", Now.AddSeconds(-index), Source(index)))
            .Append(Event("latest", Now, Source(1), "mssql"));
        var locations = Enumerable.Range(0, 501).ToDictionary(index => Source(index + 1), index => new IPLocationResult(
            Source(index + 1), "resolved", City: $"测试地点 {index}", Longitude: -159 + index % 30 * 10, Latitude: -80 + index / 30 * 10));
        await using var app = await StartAppAsync(fixtures, new StubResolver(ip => locations[ip]), new StubTarget(new("unavailable")));
        using var client = new HttpClient { BaseAddress = new Uri(Assert.Single(app.Urls)) };
        client.DefaultRequestHeaders.Add("X-Test-Identity", "viewer");

        var (_, data) = await ReadSnapshotAsync(client);
        var origins = data.GetProperty("origins").EnumerateArray().ToArray();
        Assert.InRange(origins.Length, 1, 400);
        Assert.Equal(origins.Length, origins.Select(item => item.GetProperty("id").GetString()).Distinct().Count());
        Assert.Equal(502, origins.Sum(item => item.GetProperty("connectionCount").GetInt32()));
        Assert.Equal(501, origins.Sum(item => item.GetProperty("sourceIpCount").GetInt32()));
        Assert.Equal("区域汇总", origins[0].GetProperty("locationLabel").GetString());
        Assert.Equal("mssql", origins[0].GetProperty("adapterKey").GetString());
        Assert.Equal(-159, origins[0].GetProperty("longitude").GetDouble());
        Assert.Equal(-80, origins[0].GetProperty("latitude").GetDouble());
        AssertCoverage(data, observed: 502, mapped: 502, unknown: 0, privateCount: 0, pending: 0, omitted: 402);
    }

    [Fact]
    public async Task DisabledLookupKeepsCoverageWithoutReturningSourcePositions()
    {
        var fixture = new[] { Event("public", Now, Source(1)), Event("private", Now, "192.0.2.17") };
        await using var app = await StartAppAsync(fixture, new StubResolver(Mapped, enabled: false), new StubTarget(new("disabled")));
        using var client = new HttpClient { BaseAddress = new Uri(Assert.Single(app.Urls)) };
        client.DefaultRequestHeaders.Add("X-Test-Identity", "viewer");

        var (_, data) = await ReadSnapshotAsync(client);
        Assert.False(data.GetProperty("locationEnabled").GetBoolean());
        Assert.Equal("disabled", data.GetProperty("target").GetProperty("status").GetString());
        Assert.Empty(data.GetProperty("events").EnumerateArray());
        Assert.Empty(data.GetProperty("origins").EnumerateArray());
        Assert.Empty(data.GetProperty("adapterKeys").EnumerateArray());
        AssertCoverage(data, observed: 2, mapped: 0, unknown: 1, privateCount: 1, pending: 0, omitted: 0);
    }

    private static async Task<WebApplication> StartAppAsync(IEnumerable<InteractionEvent> fixtures, StubResolver resolver, StubTarget target)
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        builder.Logging.ClearProviders();
        builder.Services.AddSingleton<TimeProvider>(new FixedClock());
        builder.Services.AddSingleton<IIPLocationResolver>(resolver);
        builder.Services.AddSingleton<IConnectionMapTarget>(target);
        builder.Services.AddSingleton<ICredentialEvidenceStore, InMemoryCredentialEvidenceStore>();
        builder.Services.AddSingleton<IInteractionEventStore>(services => new InMemoryInteractionEventStore(
            new InMemoryThreatProfileStore(), services.GetRequiredService<ICredentialEvidenceStore>()));

        var app = builder.Build();
        var store = app.Services.GetRequiredService<IInteractionEventStore>();
        foreach (var item in fixtures) Assert.True((await store.AppendAsync(item)).Recorded);
        app.Use((context, next) =>
        {
            if (context.Request.Headers["X-Test-Identity"].FirstOrDefault() is { } role)
                context.Items["CurrentUser"] = new AuthenticatedUser("isolated-viewer", "isolated-viewer", [role]);
            return next(context);
        });
        app.MapOverviewConnectionMapEndpoints();
        await app.StartAsync();
        return app;
    }

    private static async Task<(string Body, JsonElement Data)> ReadSnapshotAsync(HttpClient client, int? windowSeconds = null)
    {
        var path = windowSeconds is null ? Route : $"{Route}?windowSeconds={windowSeconds}";
        using var response = await client.GetAsync(path);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(response.Headers.CacheControl?.NoStore);
        var body = await response.Content.ReadAsStringAsync();
        using var json = JsonDocument.Parse(body);
        Assert.True(json.RootElement.GetProperty("success").GetBoolean());
        return (body, json.RootElement.GetProperty("data").Clone());
    }

    private static void AssertEvent(JsonElement item, InteractionEvent connection, string ip, string country)
    {
        // 有效地图记录包含悬浮信息所需的来源 IP 和国家，账号和报文不进入地图合同。
        Assert.Equal(new[] { "adapterKey", "country", "id", "latitude", "locationLabel", "locationSource", "locationVersion", "longitude", "occurredAtUtc", "sourceIp" },
            item.EnumerateObject().Select(field => field.Name).Order(StringComparer.Ordinal));
        Assert.Equal(connection.ConnectionId, item.GetProperty("id").GetString());
        Assert.Equal(connection.AdapterKey, item.GetProperty("adapterKey").GetString());
        Assert.Equal(ip, item.GetProperty("sourceIp").GetString());
        Assert.Equal(country, item.GetProperty("country").GetString());
        Assert.Equal(connection.OccurredAtUtc, item.GetProperty("occurredAtUtc").GetDateTimeOffset());
        Assert.Equal(0, item.GetProperty("latitude").GetDouble());
        Assert.Equal(116.2, item.GetProperty("longitude").GetDouble());
        Assert.Equal(country.Length == 0 ? "测试地区" : $"{country} · 测试地区", item.GetProperty("locationLabel").GetString());
        Assert.Equal("dbip", item.GetProperty("locationSource").GetString());
        Assert.Equal("test-v1", item.GetProperty("locationVersion").GetString());
    }

    private static void AssertSource(JsonElement item, string ip, string country)
    {
        Assert.Equal(new[] { "country", "ip" }, item.EnumerateObject().Select(field => field.Name).Order(StringComparer.Ordinal));
        Assert.Equal(ip, item.GetProperty("ip").GetString());
        Assert.Equal(country, item.GetProperty("country").GetString());
    }

    private static void AssertCoverage(JsonElement data, int observed, int mapped, int unknown, int privateCount, int pending, int omitted,
        int deferred = 0)
    {
        var coverage = data.GetProperty("coverage");
        Assert.Equal(observed, coverage.GetProperty("observed").GetInt32());
        Assert.Equal(mapped, coverage.GetProperty("mapped").GetInt32());
        Assert.Equal(unknown, coverage.GetProperty("unknown").GetInt32());
        Assert.Equal(privateCount, coverage.GetProperty("private").GetInt32());
        Assert.Equal(pending, coverage.GetProperty("pending").GetInt32());
        Assert.Equal(omitted, coverage.GetProperty("omitted").GetInt32());
        Assert.Equal(deferred, coverage.GetProperty("deferred").GetInt32());
        Assert.Equal(observed, mapped + unknown + privateCount + pending);
    }

    private static string Source(int index) => $"2001:db9:5a::{index:x}";

    private static IPLocationResult Mapped(string ip) => new(ip, "resolved", City: "测试地区", Latitude: 0, Longitude: 116.2,
        Source: "dbip", Version: "test-v1");

    private static InteractionEvent Event(string id, DateTimeOffset time, string source, string adapter = "ssh") => new()
    {
        EventId = $"event-{id}", ConnectionId = id, EventType = "ConnectionAccepted", OccurredAtUtc = time,
        SourceIp = source, DestinationIp = "192.0.2.120", AdapterKey = adapter, ListenerId = "test-listener",
        ServiceInstanceId = "test-instance", ProfileId = "test-profile", Username = "isolated-username", Password = "isolated-password",
        CredentialArtifactId = "isolated-credential-id", PayloadSummary = "isolated-payload",
    };

    private sealed class FixedClock : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => Now;
    }

    private sealed class StubResolver(Func<string, IPLocationResult> locate, bool enabled = true) : IIPLocationResolver
    {
        public List<string[]> Requests { get; } = [];

        public IPLocationBatchResult Resolve(IReadOnlyList<string> ips) =>
            throw new InvalidOperationException("地图使用独立的有界调度入口。");

        public IPLocationBatchResult ResolveForMap(IReadOnlyList<string> ips)
        {
            Requests.Add(ips.ToArray());
            // 公网形状的测试地址只在进程内合成定位结果，不发外部请求。
            return new(enabled, ips.Select(locate).ToArray());
        }
    }

    private sealed class StubTarget(ConnectionMapTarget value) : IConnectionMapTarget
    {
        public ConnectionMapTarget GetSnapshot() => value;
    }
}
