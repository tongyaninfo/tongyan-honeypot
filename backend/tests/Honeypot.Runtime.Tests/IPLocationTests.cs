using System.Diagnostics;
using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Honeypot.Api.Common;
using Honeypot.Api.Models;
using Honeypot.Api.Options;
using Honeypot.Api.Service;
using Honeypot.Api.Service.impl;
using Honeypot.Shared.Models;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Honeypot.Runtime.Tests;

public sealed class IPLocationTests
{
    private const string PublicIpFixture = "1.1.1.1";
    private const string TargetSection = "Honeypot:AttackMap:Target:";

    [Theory]
    [InlineData("10.0.0.1", "private")]
    [InlineData("172.31.255.254", "private")]
    [InlineData("192.168.1.2", "private")]
    [InlineData("::ffff:192.168.1.2", "private")]
    [InlineData("fc00::1", "private")]
    [InlineData("127.0.0.1", "reserved")]
    [InlineData("169.254.1.1", "reserved")]
    [InlineData("100.64.1.1", "reserved")]
    [InlineData("192.0.2.1", "reserved")]
    [InlineData("198.18.1.1", "reserved")]
    [InlineData("203.0.113.1", "reserved")]
    [InlineData("224.0.0.1", "reserved")]
    [InlineData("2001:db8::1", "reserved")]
    [InlineData("fe80::1", "reserved")]
    [InlineData("ff02::1", "reserved")]
    [InlineData("::1", "reserved")]
    [InlineData("1.1.1.0/24", "network")]
    [InlineData("2001:4860::/32", "network")]
    [InlineData("::ffff:1.1.1.0/120", "network")]
    [InlineData("1.1.1.1/33", "invalid")]
    [InlineData("1.1.1.1/-1", "invalid")]
    [InlineData("1.1.1.1/", "invalid")]
    [InlineData("1.1.1", "invalid")]
    [InlineData("16843009", "invalid")]
    [InlineData("010.0.0.1", "invalid")]
    [InlineData("::ffff:010.0.0.1", "invalid")]
    [InlineData("not-an-ip", "invalid")]
    [InlineData("fe80::1%en0", "invalid")]
    public void LocalClassificationDoesNotEnqueue(string ip, string status)
    {
        var adapter = new FakeAdapter();
        using var resolver = CreateResolver(new FakeSettings(new() { Enabled = true }), adapter);
        Assert.Equal(status, Assert.Single(resolver.Resolve([ip]).Items).Status);
        Assert.Equal(0, adapter.Calls);
    }

    [Fact]
    public void DefaultsAreDisabledAndLocalAddressesStillDisplay()
    {
        var store = new FakeSettings(new());
        using var resolver = CreateResolver(store, new FakeAdapter());
        var result = resolver.Resolve(["1.1.1.1", "10.0.0.1", "192.0.2.0/24"]);
        Assert.False(result.Enabled);
        Assert.Equal(new[] { "disabled", "private", "network" }, result.Items.Select(item => item.Status));
        Assert.Equal("https", store.Current.Protocol);
        Assert.Equal("ip.tongyaninfo.com", store.Current.Host);
        Assert.Equal(443, store.Current.Port);
        Assert.Equal("CZ88", store.Current.Database);
        Assert.Equal(2, store.Current.TimeoutSeconds);
    }

    [Fact]
    public void FullQueueReturnsImmediatelyAndCanonicalAddressesDeduplicate()
    {
        var adapter = new FakeAdapter();
        using var resolver = CreateResolver(new FakeSettings(new() { Enabled = true }), adapter, new() { QueueCapacity = 2 });
        var clock = Stopwatch.StartNew();
        var result = resolver.Resolve(["1.1.1.1", "::ffff:1.1.1.1", "8.8.8.8", "9.9.9.9"]);
        Assert.Equal(new[] { "pending", "pending", "pending", "busy" }, result.Items.Select(item => item.Status));
        Assert.Equal("::ffff:1.1.1.1", result.Items[1].Ip);
        Assert.True(clock.Elapsed < TimeSpan.FromMilliseconds(500));
        Assert.Equal(0, adapter.Calls);
    }

    [Fact]
    public async Task MapRequestsAdmitAtMost128NewAddressesAndKeepCacheHitsAcrossRequests()
    {
        // 合成地址只交由本地替身解析，便于验证跨批覆盖，无需外部定位服务。
        var addresses = Enumerable.Range(1, 260).Select(index => $"3000:db8::{index:x}").ToArray();
        var adapter = new FakeAdapter();
        using var resolver = CreateResolver(new FakeSettings(new() { Enabled = true }), adapter);
        var first = resolver.ResolveForMap(addresses);
        Assert.True(first.Enabled);
        Assert.All(first.Items.Take(128), item => Assert.Equal("pending", item.Status));
        Assert.All(first.Items.Skip(128), item => Assert.Equal("deferred", item.Status));
        Assert.Equal(addresses, first.Items.Select(item => item.Ip));
        Assert.Equal(0, adapter.Calls);

        using var stop = new CancellationTokenSource();
        var worker = resolver.RunAsync(stop.Token);
        try
        {
            await Until(() => adapter.Calls == 128 && adapter.Active == 0 &&
                Assert.Single(resolver.ResolveForMap([addresses[127]]).Items).Status == "resolved");
            var next = resolver.ResolveForMap([.. addresses.Skip(128), .. addresses.Take(128)]);
            Assert.All(next.Items.Take(128), item => Assert.Equal("pending", item.Status));
            Assert.All(next.Items.Skip(128).Take(4), item => Assert.Equal("deferred", item.Status));
            Assert.All(next.Items.Skip(132), item => Assert.Equal("resolved", item.Status));
        }
        finally { stop.Cancel(); await worker; }
    }

    [Fact]
    public async Task MapRequestsDeferWhenQueueIsFullAndRecognizeExistingWorkAndDisabledSettings()
    {
        var settings = new FakeSettings(new() { Enabled = true });
        var adapter = new FakeAdapter();
        using var resolver = CreateResolver(settings, adapter, new() { QueueCapacity = 2 });
        var addresses = new[] { "3000:db8::1", "3000:db8::2", "3000:db8::3", "3000:DB8::1", "192.0.2.1" };
        var busy = resolver.ResolveForMap(addresses);
        Assert.Equal(new[] { "pending", "pending", "deferred", "pending", "reserved" }, busy.Items.Select(item => item.Status));
        Assert.Equal(addresses, busy.Items.Select(item => item.Ip));
        Assert.Equal("busy", Assert.Single(resolver.Resolve([addresses[2]]).Items).Status);

        await settings.SaveAsync(settings.Current with { Enabled = false }, default);
        var disabled = resolver.ResolveForMap(addresses);
        Assert.False(disabled.Enabled);
        Assert.Equal(new[] { "disabled", "disabled", "disabled", "disabled", "reserved" }, disabled.Items.Select(item => item.Status));
        Assert.Equal(0, adapter.Calls);
    }

    [Fact]
    public async Task WorkersRespectConcurrencyAndCacheLimit()
    {
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var adapter = new FakeAdapter(async (ip, _, token) => { await gate.Task.WaitAsync(token); return new(ip, "resolved", "sample"); });
        using var resolver = CreateResolver(new FakeSettings(new() { Enabled = true }), adapter,
            new() { Concurrency = 2, CacheCapacity = 2 });
        using var stop = new CancellationTokenSource();
        var worker = resolver.RunAsync(stop.Token);
        try
        {
            resolver.Resolve(["1.1.1.1", "8.8.8.8", "9.9.9.9"]);
            await Until(() => adapter.Calls == 2);
            Assert.Equal(2, adapter.MaxActive);
            Assert.Equal("pending", Assert.Single(resolver.Resolve(["1.1.1.1"]).Items).Status);
            gate.SetResult();
            await Until(() => adapter.Calls == 3 && adapter.Active == 0);
            await Until(() => Assert.Single(resolver.Resolve(["9.9.9.9"]).Items).Status == "resolved");
            // 两条缓存容量无法保留三条结果，访问全部 IP 至少一条需要重新入队。
            Assert.Contains(resolver.Resolve(["1.1.1.1", "8.8.8.8", "9.9.9.9"]).Items, item => item.Status == "pending");
            Assert.Equal(2, adapter.MaxActive);
        }
        finally { stop.Cancel(); await worker; }
    }

    [Fact]
    public async Task FailuresAreCachedThenExpire()
    {
        var time = new TestTime();
        var adapter = new FakeAdapter((ip, _, _) => Task.FromResult(new IPLocationResult(ip, "failed")));
        using var resolver = CreateResolver(new FakeSettings(new() { Enabled = true }), adapter, time: time);
        using var stop = new CancellationTokenSource();
        var worker = resolver.RunAsync(stop.Token);
        try
        {
            resolver.Resolve(["1.1.1.1"]);
            await Until(() => Assert.Single(resolver.Resolve(["1.1.1.1"]).Items).Status == "failed");
            resolver.Resolve(["1.1.1.1"]);
            Assert.Equal(1, adapter.Calls);
            time.Advance(TimeSpan.FromMinutes(2));
            Assert.Equal("pending", Assert.Single(resolver.Resolve(["1.1.1.1"]).Items).Status);
            await Until(() => adapter.Calls == 2);
        }
        finally { stop.Cancel(); await worker; }
    }

    [Fact]
    public async Task ConfigurationChangeCancelsOldWorkAndRejectsLateResults()
    {
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var capturedToken = CancellationToken.None;
        var adapter = new FakeAdapter(async (ip, settings, token) =>
        {
            capturedToken = token;
            await gate.Task; // 故意模拟无视取消的供应方，验证代际检查仍隔离旧结果。
            return new(ip, "resolved", settings.Database);
        });
        var store = new FakeSettings(new() { Enabled = true });
        using var resolver = CreateResolver(store, adapter, new() { Concurrency = 1 });
        using var stop = new CancellationTokenSource();
        var worker = resolver.RunAsync(stop.Token);
        try
        {
            resolver.Resolve(["1.1.1.1", "8.8.8.8"]);
            await Until(() => adapter.Calls == 1);
            await store.SaveAsync(store.Current with { Enabled = false }, default);
            Assert.True(capturedToken.IsCancellationRequested);
            gate.SetResult();
            await Until(() => adapter.Active == 0);
            Assert.Equal("disabled", Assert.Single(resolver.Resolve(["1.1.1.1"]).Items).Status);
            Assert.Equal(1, adapter.Calls);
            await store.SaveAsync(store.Current with { Enabled = true, Database = "ipinfo" }, default);
            Assert.Equal("pending", Assert.Single(resolver.Resolve(["1.1.1.1"]).Items).Status);
            await Until(() => Assert.Single(resolver.Resolve(["1.1.1.1"]).Items).DisplayName == "ipinfo");
        }
        finally { gate.TrySetResult(); stop.Cancel(); await worker; }
    }

    [Theory]
    [InlineData("CZ88")]
    [InlineData("ip2location")]
    [InlineData("ip2region")]
    [InlineData("dbip")]
    [InlineData("ipinfo")]
    [InlineData("geolite2")]
    public async Task AdapterReadsAllSixDatabaseContracts(string database)
    {
        Uri? observed = null;
        using var adapter = new TongYanIPLocation(new HttpClient(new FakeHttp((request, _) =>
        {
            observed = request.RequestUri;
            return Task.FromResult(JsonResponse(Payload(database)));
        })));
        var result = await adapter.ResolveAsync("1.1.1.1", new() { Database = database }, default);
        Assert.Equal("resolved", result.Status);
        Assert.Equal("国家", result.Country);
        Assert.Equal("省", result.Province);
        Assert.Equal("市", result.City);
        Assert.Equal("", result.District);
        Assert.Equal($"?ip=1.1.1.1&db={database}&format=json", observed!.Query);
        Assert.Equal("ip.tongyaninfo.com", observed.Host);
        Assert.Equal("https", observed.Scheme);
    }

    [Theory]
    [InlineData("0", "0", true)]
    [InlineData("-90", "180", true)]
    [InlineData("90.01", "45", false)]
    [InlineData("0", "181", false)]
    [InlineData("null", "45", false)]
    [InlineData("12.34", "null", false)]
    [InlineData("1e1000", "0", false)]
    [InlineData("\"12.34\"", "0", false)]
    public async Task AdapterUsesOnlySelectedProviderCoordinatePair(string latitude, string longitude, bool expected)
    {
        var payload = """
            {"success":true,"data":{"ip":"PUBLIC_IP","sources":[
              {"id":"ip2location","status":"success","version":"other","fields":{"country":"other","latitude":55,"longitude":60}},
              {"id":"geolite2","status":"success","version":"selected-version","fields":{"country":"test","latitude":LATITUDE,"longitude":LONGITUDE}}
            ]}}
            """.Replace("PUBLIC_IP", PublicIpFixture, StringComparison.Ordinal)
                .Replace("LATITUDE", latitude, StringComparison.Ordinal).Replace("LONGITUDE", longitude, StringComparison.Ordinal);
        using var adapter = new TongYanIPLocation(new HttpClient(new FakeHttp((_, _) => Task.FromResult(JsonResponse(payload)))));
        var result = await adapter.ResolveAsync(PublicIpFixture, new() { Database = "geolite2" }, default);
        Assert.Equal("resolved", result.Status);
        Assert.Equal("test", result.Country);
        Assert.Equal("geolite2", result.Source);
        Assert.Equal("selected-version", result.Version);
        Assert.Equal(expected, IPLocationAddress.HasCoordinates(result.Latitude, result.Longitude));
        if (expected)
        {
            Assert.Equal(double.Parse(latitude, System.Globalization.CultureInfo.InvariantCulture), result.Latitude);
            Assert.Equal(double.Parse(longitude, System.Globalization.CultureInfo.InvariantCulture), result.Longitude);
        }
        else
        {
            Assert.Null(result.Latitude);
            Assert.Null(result.Longitude);
        }
    }

    [Fact]
    public async Task TargetProbeUsesSameOriginTextContractAndRejectsNonPublicOrInvalidBodies()
    {
        var response = PublicIpFixture + "\n";
        var media = "text/plain";
        var calls = 0;
        using var probe = new ConnectionMapPublicIpProbe(new HttpClient(new FakeHttp((request, _) =>
        {
            calls++;
            Assert.Equal(new Uri("https://geo.example.test:8443/"), request.RequestUri);
            Assert.Equal("text/plain", Assert.Single(request.Headers.Accept).MediaType);
            Assert.NotNull(request.Headers.CacheControl);
            Assert.True(request.Headers.CacheControl.NoStore);
            Assert.Null(request.Headers.Authorization);
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(response, Encoding.UTF8, media) });
        })));
        var settings = new IPLocationSettings { Host = "geo.example.test", Port = 8443, Enabled = true };
        Assert.Null(await probe.DiscoverAsync(settings with { Enabled = false }, default));
        Assert.Equal(0, calls);
        Assert.Equal(PublicIpFixture, await probe.DiscoverAsync(settings, default));
        foreach (var malformed in new[] { "192.0.2.1", "fe80::1", PublicIpFixture + ", 192.0.2.1", new string('1', 129) })
        {
            response = malformed;
            Assert.Null(await probe.DiscoverAsync(settings, default));
        }
        response = PublicIpFixture;
        media = "application/json";
        Assert.Null(await probe.DiscoverAsync(settings, default));
    }

    [Fact]
    public async Task TargetUsesManualCoordinatesBeforeIpAndRejectsInvalidPartialConfiguration()
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            [TargetSection + "Latitude"] = "0",
            [TargetSection + "Longitude"] = "0",
            [TargetSection + "Label"] = "测试节点",
            [TargetSection + "PublicIp"] = PublicIpFixture,
        }).Build();
        await using var provider = CreateTargetProvider(configuration, new FakeSettings(new()), new TestTime(), (_, _) =>
                throw new InvalidOperationException("Explicit coordinates must not request IP location"),
            (_, _) => throw new InvalidOperationException("Explicit coordinates must not probe public IP"));
        var target = provider.GetRequiredService<IConnectionMapTarget>();
        Assert.Equal(new ConnectionMapTarget("ready", "测试节点", 0, 0, "configuredCoordinates"), target.GetSnapshot());
        configuration[TargetSection + "Latitude"] = "invalid";
        configuration.Reload();
        Assert.Equal(new ConnectionMapTarget("unavailable", "测试节点", Source: "configuredCoordinates"), target.GetSnapshot());
    }

    [Fact]
    public async Task ConfiguredTargetIpUsesSelectedDatabaseWithoutDiscovery()
    {
        const string changedIp = "2001:db9:5a::24";
        var root = Path.Combine(Path.GetTempPath(), "honeypot-map-configured-" + Guid.NewGuid().ToString("N"));
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Honeypot:DataDirectory"] = root,
            [TargetSection + "PublicIp"] = PublicIpFixture,
        }).Build();
        var settings = new FakeSettings(new() { Enabled = true, Database = "dbip" });
        var clock = new TestTime();
        var lookups = 0;
        await using var provider = CreateTargetProvider(configuration, settings, clock, (ip, current) =>
        {
            Assert.Equal("dbip", current.Database);
            var attempt = Interlocked.Increment(ref lookups);
            if (attempt == 3)
            {
                Assert.Equal(changedIp, ip);
                return new(ip, "failed");
            }
            Assert.Equal(PublicIpFixture, ip);
            return attempt == 1
                ? new(ip, "resolved", City: "测试城市", Latitude: 20, Longitude: 70, Source: "dbip")
                : new(ip, "resolved", City: "测试城市", Latitude: 23, Longitude: 70, Source: "dbip");
        }, (_, _) => throw new InvalidOperationException("Configured public IP must not start discovery"));
        var hosted = Assert.Single(provider.GetServices<IHostedService>());
        var target = provider.GetRequiredService<IConnectionMapTarget>();
        Assert.Equal("pending", target.GetSnapshot().Status);
        await hosted.StartAsync(default);
        try
        {
            await Until(() => target.GetSnapshot().Status == "ready");
            Assert.Equal(new ConnectionMapTarget("ready", "测试城市", 20, 70, "configuredPublicIp", UpdatedAtUtc: clock.GetUtcNow()),
                target.GetSnapshot());
            clock.Advance(TimeSpan.FromDays(1));
            await Until(() => target.GetSnapshot().Latitude == 23);
            Assert.Equal(2, Volatile.Read(ref lookups));
            Assert.Equal(clock.GetUtcNow(), target.GetSnapshot().UpdatedAtUtc);

            // 显式目标地址改变属于另一个目标，即使上一份缓存仍然有效也不能复用。
            configuration[TargetSection + "PublicIp"] = changedIp;
            configuration.Reload();
            Assert.Null(target.GetSnapshot().Latitude);
            await Until(() => target.GetSnapshot().Status == "unavailable");
            Assert.Equal(3, Volatile.Read(ref lookups));
            Assert.Null(target.GetSnapshot().UpdatedAtUtc);
            Assert.False(target.GetSnapshot().Stale);
        }
        finally { await hosted.StopAsync(default); }
    }

    [Theory]
    [InlineData(true, false)]
    [InlineData(false, false)]
    [InlineData(true, true)]
    public async Task ChangingLookupSettingsKeepsFreshTargetUntilTheNewLookupSucceeds(bool changeEndpoint, bool revertBeforeRecovery)
    {
        var root = Path.Combine(Path.GetTempPath(), "honeypot-map-switch-" + Guid.NewGuid().ToString("N"));
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["Honeypot:DataDirectory"] = root }).Build();
        var originalSettings = new IPLocationSettings
            { Enabled = true, Database = "ip2location", Host = "geo-public.example.test", TimeoutSeconds = 30 };
        var newSettings = changeEndpoint
            ? originalSettings with { Protocol = "http", Host = "geo-lan.example.test", Port = 5080 }
            : originalSettings with { Database = "dbip" };
        var recoverySettings = revertBeforeRecovery ? originalSettings : newSettings;
        var settings = new FakeSettings(originalSettings);
        var clock = new TestTime();
        var probes = 0;
        var lookups = 0;
        var switchedProbeStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var switchedProbeResult = new TaskCompletionSource<HttpResponseMessage>(TaskCreationOptions.RunContinuationsAsynchronously);

        await using var provider = CreateTargetProvider(configuration, settings, clock, (ip, current) =>
        {
            Interlocked.Increment(ref lookups);
            Assert.Equal(PublicIpFixture, ip);
            return Volatile.Read(ref probes) switch
            {
                1 when current == originalSettings => new(ip, "resolved", City: "旧位置", Latitude: 20, Longitude: 70, Source: current.Database),
                2 when current == newSettings => new(ip, "failed"),
                3 when current == recoverySettings => new(ip, "resolved", City: "新位置", Latitude: 24, Longitude: 74, Source: current.Database),
                _ => throw new InvalidOperationException("Unexpected lookup settings"),
            };
        }, async (request, cancellationToken) =>
        {
            var attempt = Interlocked.Increment(ref probes);
            var expected = attempt switch { 1 => originalSettings, 2 => newSettings, _ => recoverySettings };
            Assert.Equal(new UriBuilder(expected.Protocol, expected.Host, expected.Port, "/").Uri, request.RequestUri);
            if (attempt != 2) return PlainIp(PublicIpFixture);
            switchedProbeStarted.TrySetResult();
            return await switchedProbeResult.Task.WaitAsync(cancellationToken);
        });
        var hosted = Assert.Single(provider.GetServices<IHostedService>());
        var target = provider.GetRequiredService<IConnectionMapTarget>();
        await hosted.StartAsync(default);
        try
        {
            await Until(() => File.Exists(Path.Combine(root, "connection-map-target-cache.json")));
            var initial = target.GetSnapshot();
            Assert.Equal("ready", initial.Status);
            Assert.Equal(20, initial.Latitude);
            Assert.False(initial.Stale);
            clock.Advance(TimeSpan.FromMinutes(1));

            await settings.SaveAsync(newSettings, default);
            Assert.Equal(initial with { Stale = true }, target.GetSnapshot());
            await switchedProbeStarted.Task.WaitAsync(TimeSpan.FromSeconds(3));
            Assert.Equal(initial with { Stale = true }, target.GetSnapshot());

            // LAN 根路径回显私网时不应调用定位；切换数据库时模拟实际查询后失败。
            var failureCompleted = clock.ObserveNextRead();
            switchedProbeResult.SetResult(PlainIp(changeEndpoint ? "192.168.1.2" : PublicIpFixture));
            await failureCompleted.WaitAsync(TimeSpan.FromSeconds(3));
            Assert.Equal(changeEndpoint ? 1 : 2, Volatile.Read(ref lookups));
            Assert.Equal(initial with { Stale = true }, target.GetSnapshot());

            if (revertBeforeRecovery)
            {
                // 回切已有磁盘缓存的入口也要立即查一次，不能直接把旧坐标标记为本次已确认。
                await settings.SaveAsync(recoverySettings, default);
                Assert.Equal(initial with { Stale = true }, target.GetSnapshot());
            }
            else clock.Advance(TimeSpan.FromMinutes(16));
            await Until(() => target.GetSnapshot().Latitude == 24);
            Assert.Equal(new ConnectionMapTarget("ready", "新位置", 24, 74, "detectedPublicIp", UpdatedAtUtc: clock.GetUtcNow()),
                target.GetSnapshot());
            Assert.Equal(3, Volatile.Read(ref probes));
            Assert.Equal(changeEndpoint ? 2 : 3, Volatile.Read(ref lookups));
        }
        finally { await hosted.StopAsync(default); }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task TargetCacheSurvivesRefreshFailureRestartAndDatabaseChange(bool legacyCacheWithDifferentEndpoint)
    {
        var root = Path.Combine(Path.GetTempPath(), "honeypot-map-target-" + Guid.NewGuid().ToString("N"));
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["Honeypot:DataDirectory"] = root }).Build();
        var settings = new FakeSettings(new() { Enabled = true, Database = "geolite2" });
        var clock = new TestTime();
        var sent = 0;
        var cachePath = Path.Combine(root, "connection-map-target-cache.json");
        async Task<DateTimeOffset> MakeInitialCacheAsync()
        {
            await using var provider = CreateTargetProvider(configuration, settings, clock,
                (ip, _) => new(ip, "resolved", Latitude: -1.5, Longitude: 171, Source: "geolite2"),
                (_, _) =>
                {
                    Interlocked.Increment(ref sent);
                    return Task.FromResult(PlainIp(PublicIpFixture));
                });
            var hosted = Assert.Single(provider.GetServices<IHostedService>());
            var target = provider.GetRequiredService<IConnectionMapTarget>();
            await hosted.StartAsync(default);
            try
            {
                await Until(() => File.Exists(cachePath));
                var snapshot = target.GetSnapshot();
                Assert.Equal("detectedPublicIp", snapshot.Source);
                Assert.Equal(-1.5, snapshot.Latitude);
                Assert.Equal(171, snapshot.Longitude);
                Assert.False(snapshot.Stale);
                Assert.DoesNotContain(PublicIpFixture, await File.ReadAllTextAsync(cachePath));
                return snapshot.UpdatedAtUtc!.Value;
            }
            finally { await hosted.StopAsync(default); }
        }

        var initial = await MakeInitialCacheAsync();
        Assert.Equal(1, Volatile.Read(ref sent));
        if (legacyCacheWithDifferentEndpoint)
        {
            // 模拟修复前没有目标身份字段的自动探测缓存。仅改写本测试的隔离副本。
            var legacy = JsonNode.Parse(await File.ReadAllTextAsync(cachePath))!.AsObject();
            legacy.Remove("targetFingerprint");
            await File.WriteAllTextAsync(cachePath, legacy.ToJsonString());
            clock.Advance(TimeSpan.FromMinutes(1));
            await settings.SaveAsync(settings.Current with { Host = "geo-lan.example.test" }, default);
        }
        else clock.Advance(TimeSpan.FromDays(1));
        await using var reloaded = CreateTargetProvider(configuration, settings, clock,
            (_, _) => throw new InvalidOperationException("A failed probe must not query location"),
            (_, _) =>
            {
                Interlocked.Increment(ref sent);
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));
            });
        var restarting = Assert.Single(reloaded.GetServices<IHostedService>());
        var restored = reloaded.GetRequiredService<IConnectionMapTarget>();
        await restarting.StartAsync(default);
        try
        {
            await Until(() => Volatile.Read(ref sent) == 2 && restored.GetSnapshot().Stale);
            var snapshot = restored.GetSnapshot();
            Assert.Equal("ready", snapshot.Status);
            Assert.Equal(initial, snapshot.UpdatedAtUtc);
            Assert.Equal(-1.5, snapshot.Latitude);
            for (var index = 0; index < 10; index++) Assert.True(restored.GetSnapshot().Stale);
            Assert.Equal(2, Volatile.Read(ref sent));
            await settings.SaveAsync(settings.Current with { Database = "dbip" }, default);
            Assert.Equal(snapshot, restored.GetSnapshot());
            await Until(() => Volatile.Read(ref sent) == 3);
            await settings.SaveAsync(settings.Current with { Database = "geolite2" }, default);
            await Until(() => Volatile.Read(ref sent) == 4);
            Assert.True(restored.GetSnapshot().Stale);
            Assert.Equal(initial, restored.GetSnapshot().UpdatedAtUtc);
            await settings.SaveAsync(settings.Current with { Enabled = false }, default);
            Assert.Equal("disabled", restored.GetSnapshot().Status);
        }
        finally { await restarting.StopAsync(default); }
    }

    [Theory]
    [InlineData("notFound", "resolved")]
    [InlineData("timeout", "failed")]
    [InlineData("unsupported", "failed")]
    [InlineData("unavailable", "failed")]
    public async Task AdapterDistinguishesNoDataFromProviderFailure(string status, string expected)
    {
        using var adapter = new TongYanIPLocation(new HttpClient(new FakeHttp((_, _) => Task.FromResult(JsonResponse(Payload("CZ88", status))))));
        var result = await adapter.ResolveAsync("1.1.1.1", new(), default);
        Assert.Equal(expected, result.Status);
        if (expected == "resolved") Assert.Equal("未查询到归属地", result.DisplayName);
    }

    [Theory]
    [InlineData("ipinfo", "1.1.1.1")]
    [InlineData("CZ88", "8.8.8.8")]
    public async Task AdapterRejectsMismatchedSourceOrAddress(string database, string returnedIp)
    {
        using var adapter = new TongYanIPLocation(new HttpClient(new FakeHttp((_, _) => Task.FromResult(JsonResponse(Payload(database, ip: returnedIp))))));
        Assert.Equal("failed", (await adapter.ResolveAsync("1.1.1.1", new(), default)).Status);
    }

    [Fact]
    public async Task AdapterHandlesEmptyMalformedOversizedAndSlowBodies()
    {
        foreach (var body in new[] { "not-json", new string('x', 65537), Payload("CZ88", fields: new { country = (string?)null, region = (string?)null }) })
        {
            using var adapter = new TongYanIPLocation(new HttpClient(new FakeHttp((_, _) => Task.FromResult(JsonResponse(body)))));
            var result = await adapter.ResolveAsync("1.1.1.1", new(), default);
            Assert.Equal(body.StartsWith('{') ? "resolved" : "failed", result.Status);
            if (result.Status == "resolved") Assert.Equal("未查询到归属地", result.DisplayName);
        }
        using var slowAdapter = new TongYanIPLocation(new HttpClient(new FakeHttp((_, _) => Task.FromResult(
            new HttpResponseMessage(HttpStatusCode.OK) { Content = new StreamContent(new SlowStream()) }))));
        var elapsed = Stopwatch.StartNew();
        Assert.Equal("failed", (await slowAdapter.ResolveAsync("1.1.1.1", new() { TimeoutSeconds = 0.1 }, default)).Status);
        Assert.InRange(elapsed.Elapsed.TotalSeconds, 0.05, 2);
    }

    [Fact]
    public async Task SettingsPersistAndInvalidOrCorruptSettingsStayClosed()
    {
        var root = Path.Combine(Path.GetTempPath(), "honeypot-ip-settings-" + Guid.NewGuid().ToString("N"));
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["Honeypot:DataDirectory"] = root }).Build();
        var environment = new TestEnvironment();
        var store = new FileIPLocationSettingsStore(configuration, environment, NullLogger<FileIPLocationSettingsStore>.Instance);
        Assert.False(store.Current.Enabled);
        await store.SaveAsync(new() { Enabled = true, Database = "ipinfo" }, default);
        var reloaded = new FileIPLocationSettingsStore(configuration, environment, NullLogger<FileIPLocationSettingsStore>.Instance);
        Assert.True(reloaded.Current.Enabled);
        Assert.Equal("ipinfo", reloaded.Current.Database);
        await File.WriteAllTextAsync(Path.Combine(root, "ip-location-settings.json"), "invalid-json");
        var recovered = new FileIPLocationSettingsStore(configuration, environment, NullLogger<FileIPLocationSettingsStore>.Instance);
        Assert.False(recovered.Current.Enabled);
        await recovered.SaveAsync(new(), default);
        using var repairedJson = JsonDocument.Parse(await File.ReadAllTextAsync(Path.Combine(root, "ip-location-settings.json")));
        Assert.False(repairedJson.RootElement.GetProperty("enabled").GetBoolean());
        foreach (var invalid in new[] { new IPLocationSettings { Host = "https://example.com/path" }, new() { Host = "user@example.com" },
            new() { Protocol = "ftp" }, new() { Database = "all" }, new() { Port = 0 }, new() { TimeoutSeconds = double.NaN }, new() { TimeoutSeconds = 31 } })
            Assert.False(IPLocationSettingsValidation.TryNormalize(invalid, out _));
    }

    [Fact]
    public void DependencyInjectionCanDisposeResolverAliasesSafely()
    {
        using var provider = new ServiceCollection().AddSingleton<IIPLocationSettingsStore>(new FakeSettings(new()))
            .AddSingleton<IIPLocation>(new FakeAdapter()).AddSingleton(new IPLocationOptions()).AddSingleton(TimeProvider.System)
            .AddSingleton<IPLocationResolver>().AddSingleton<IIPLocationResolver>(services => services.GetRequiredService<IPLocationResolver>())
            .BuildServiceProvider();
        Assert.Same(provider.GetRequiredService<IPLocationResolver>(), provider.GetRequiredService<IIPLocationResolver>());
    }

    [Fact]
    public async Task HttpContractsEnforceAuthorizationValidationAndImmediateResponse()
    {
        var builder = WebApplication.CreateBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        var store = new FakeSettings(new());
        var adapter = new FakeAdapter();
        using var resolver = CreateResolver(store, adapter);
        builder.Services.AddSingleton<IIPLocationSettingsStore>(store);
        builder.Services.AddSingleton<IIPLocationResolver>(resolver);
        await using var app = builder.Build();
        app.Use((context, next) =>
        {
            if (context.Request.Headers["X-Test-Role"].FirstOrDefault() is { } role)
                context.Items["CurrentUser"] = new AuthenticatedUser("test", "test", [role]);
            return next(context);
        });
        app.MapIPLocationEndpoints();
        await app.StartAsync();
        using var client = new HttpClient { BaseAddress = new Uri(app.Urls.Single()) };
        try
        {
            Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/api/v1/settings/ip-location")).StatusCode);
            client.DefaultRequestHeaders.Add("X-Test-Role", "viewer");
            Assert.Equal(HttpStatusCode.Forbidden, (await client.GetAsync("/api/v1/settings/ip-location")).StatusCode);
            Assert.Equal(HttpStatusCode.Forbidden, (await client.PutAsJsonAsync("/api/v1/settings/ip-location", new IPLocationSettings())).StatusCode);
            using var local = await client.PostAsJsonAsync("/api/v1/ip-locations/resolve", new { ips = new[] { "1.1.1.1", "10.0.0.1" } });
            Assert.Equal(HttpStatusCode.OK, local.StatusCode);
            Assert.Contains("disabled", await local.Content.ReadAsStringAsync());
            client.DefaultRequestHeaders.Remove("X-Test-Role");
            client.DefaultRequestHeaders.Add("X-Test-Role", "Administrator");
            using var saved = await client.PutAsJsonAsync("/api/v1/settings/ip-location", new IPLocationSettings { Enabled = true });
            Assert.Equal(HttpStatusCode.OK, saved.StatusCode);
            Assert.True(saved.Headers.CacheControl!.NoStore);
            using var response = await client.PostAsJsonAsync("/api/v1/ip-locations/resolve", new { ips = new[] { "1.1.1.1" } });
            Assert.Contains("pending", await response.Content.ReadAsStringAsync());
            Assert.Equal(0, adapter.Calls);
            foreach (var body in new[] { "{", "null", "", "{\"ips\":[]}", JsonSerializer.Serialize(new { ips = Enumerable.Repeat("1.1.1.1", 101) }), new string('x', 17000) })
            {
                using var invalid = await client.PostAsync("/api/v1/ip-locations/resolve", new StringContent(body, Encoding.UTF8, "application/json"));
                Assert.Equal(HttpStatusCode.BadRequest, invalid.StatusCode);
                Assert.Contains("VALIDATION_ERROR", await invalid.Content.ReadAsStringAsync());
            }
            using var badSettings = await client.PutAsJsonAsync("/api/v1/settings/ip-location", new IPLocationSettings { Host = "https://example.com/" });
            Assert.Equal(HttpStatusCode.BadRequest, badSettings.StatusCode);
        }
        finally { await app.StopAsync(); }
    }

    private static IPLocationResolver CreateResolver(FakeSettings store, FakeAdapter adapter, IPLocationOptions? options = null, TimeProvider? time = null) =>
        new(store, adapter, options ?? new(), time ?? TimeProvider.System);

    private static ServiceProvider CreateTargetProvider(IConfiguration configuration, FakeSettings settings, TimeProvider clock,
        Func<string, IPLocationSettings, IPLocationResult> resolve, Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) =>
        new ServiceCollection().AddLogging().AddSingleton(configuration)
            .AddSingleton<IHostEnvironment>(new TestEnvironment()).AddSingleton<IIPLocationSettingsStore>(settings)
            .AddSingleton<IIPLocation>(new FakeAdapter((ip, current, _) => Task.FromResult(resolve(ip, current)))).AddSingleton(clock)
            .AddConnectionMapTarget().AddSingleton(_ => new ConnectionMapPublicIpProbe(new HttpClient(new FakeHttp(send))))
            .BuildServiceProvider();

    private static async Task Until(Func<bool> condition)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        while (!condition()) await Task.Delay(10, timeout.Token);
    }

    private static string Payload(string database, string status = "success", string ip = PublicIpFixture, object? fields = null) => JsonSerializer.Serialize(new
    {
        success = true, data = new { ip, status = "success", sources = new[] { new { id = database, status,
            fields = fields ?? new { country = "国家", region = "省", city = "市", isp = "运营商" } } } }
    });

    private static HttpResponseMessage JsonResponse(string json) => new(HttpStatusCode.OK) { Content = new StringContent(json, Encoding.UTF8, "application/json") };

    private static HttpResponseMessage PlainIp(string ip) => new(HttpStatusCode.OK)
        { Content = new StringContent(ip + "\n", Encoding.UTF8, "text/plain") };

    private sealed class FakeSettings(IPLocationSettings current) : IIPLocationSettingsStore
    {
        public IPLocationSettings Current { get; private set; } = current;
        public event Action<IPLocationSettings>? Changed;
        public Task SaveAsync(IPLocationSettings settings, CancellationToken cancellationToken)
        {
            Current = settings;
            Changed?.Invoke(settings);
            return Task.CompletedTask;
        }
    }

    private sealed class FakeAdapter(Func<string, IPLocationSettings, CancellationToken, Task<IPLocationResult>>? resolve = null) : IIPLocation
    {
        public int Calls;
        public int Active;
        public int MaxActive;
        public async Task<IPLocationResult> ResolveAsync(string ip, IPLocationSettings settings, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref Calls);
            var active = Interlocked.Increment(ref Active);
            InterlockedExtensions.Max(ref MaxActive, active);
            try { return resolve is null ? new(ip, "resolved", "sample") : await resolve(ip, settings, cancellationToken); }
            finally { Interlocked.Decrement(ref Active); }
        }
    }

    private static class InterlockedExtensions
    {
        public static void Max(ref int location, int value)
        {
            int current;
            do { current = Volatile.Read(ref location); if (current >= value) return; }
            while (Interlocked.CompareExchange(ref location, value, current) != current);
        }
    }

    private sealed class FakeHttp(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) => send(request, cancellationToken);
    }

    private sealed class SlowStream : MemoryStream
    {
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            await Task.Delay(Timeout.Infinite, cancellationToken);
            return 0;
        }
    }

    private sealed class TestTime : TimeProvider
    {
        private long _now = DateTimeOffset.UtcNow.UtcTicks;
        private TaskCompletionSource? _nextRead;

        public override DateTimeOffset GetUtcNow()
        {
            var now = new DateTimeOffset(Interlocked.Read(ref _now), TimeSpan.Zero);
            Interlocked.Exchange(ref _nextRead, null)?.SetResult();
            return now;
        }

        public void Advance(TimeSpan duration) => Interlocked.Add(ref _now, duration.Ticks);

        public Task ObserveNextRead()
        {
            var next = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            Volatile.Write(ref _nextRead, next);
            return next.Task;
        }
    }

    private sealed class TestEnvironment : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = "Testing";
        public string ApplicationName { get; set; } = "Tests";
        public string ContentRootPath { get; set; } = Path.GetTempPath();
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}
