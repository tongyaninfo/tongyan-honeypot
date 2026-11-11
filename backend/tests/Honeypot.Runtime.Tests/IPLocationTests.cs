using System.Diagnostics;
using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
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

    private static async Task Until(Func<bool> condition)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        while (!condition()) await Task.Delay(10, timeout.Token);
    }

    private static string Payload(string database, string status = "success", string ip = "1.1.1.1", object? fields = null) => JsonSerializer.Serialize(new
    {
        success = true, data = new { ip, status = "success", sources = new[] { new { id = database, status,
            fields = fields ?? new { country = "国家", region = "省", city = "市", isp = "运营商" } } } }
    });

    private static HttpResponseMessage JsonResponse(string json) => new(HttpStatusCode.OK) { Content = new StringContent(json, Encoding.UTF8, "application/json") };

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
        private DateTimeOffset _now = DateTimeOffset.UtcNow;
        public override DateTimeOffset GetUtcNow() => _now;
        public void Advance(TimeSpan duration) => _now += duration;
    }

    private sealed class TestEnvironment : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = "Testing";
        public string ApplicationName { get; set; } = "Tests";
        public string ContentRootPath { get; set; } = Path.GetTempPath();
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}
