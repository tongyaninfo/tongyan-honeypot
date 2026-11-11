using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Honeypot.Api.Common;
using Honeypot.Api.Models;
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
using Xunit;

namespace Honeypot.Runtime.Tests;

public sealed class SyslogSettingsTests
{
    [Fact]
    public async Task SettingsAreVersionedAndCopiesCannotMutateTheLiveConfiguration()
    {
        var (store, configuration) = NewStore();
        Assert.False(store.Current.Settings.Enabled);
        Assert.StartsWith("tongyan-honeypot-", store.Current.Hostname);
        var target = Target() with { IgnoredSeverities = [4], Facility = 20 };
        var original = new SyslogSettings { Enabled = true, Targets = [target] };
        var saved = await store.SaveAsync(original, 0);
        Assert.Equal(1, saved.Revision);
        original.Targets[0].IgnoredSeverities![0] = 7;
        saved.Settings.Targets[0] = Target() with { Host = "tampered.invalid" };
        Assert.Empty(store.Current.Settings.Targets[0].IgnoredSeverities!);
        Assert.Equal(SyslogTarget.DefaultFacility, store.Current.Settings.Targets[0].Facility);
        Assert.Equal("syslog.example.invalid", store.Current.Settings.Targets[0].Host);
        Assert.Same(((ISyslogSettingsStore)store).DeliverySnapshot, ((ISyslogSettingsStore)store).DeliverySnapshot);
        await Assert.ThrowsAsync<SyslogSettingsConflictException>(() => store.SaveAsync(new(), 0));
        // 旧版本写入的过滤和 Facility 字段在重新加载时也会归一化。
        var path = Path.Combine(configuration["Honeypot:DataDirectory"]!, "syslog", "settings.json");
        await File.WriteAllTextAsync(path, JsonSerializer.Serialize(new { Settings = original, Revision = 1 }, new JsonSerializerOptions(JsonSerializerDefaults.Web)));
        var reloaded = new FileSyslogSettingsStore(configuration, new TestEnvironment());
        Assert.Equal(1, reloaded.Current.Revision);
        Assert.True(reloaded.Current.Settings.Enabled);
        Assert.False(reloaded.Current.Settings.Targets[0].IgnoreSslErrors);
        Assert.Empty(reloaded.Current.Settings.Targets[0].IgnoredSeverities!);
        Assert.Equal(SyslogTarget.DefaultFacility, reloaded.Current.Settings.Targets[0].Facility);
    }

    [Fact]
    public async Task ConcurrentSavesDoNotLoseUpdatesAndBrokenFilesArePreserved()
    {
        var (store, configuration) = NewStore();
        async Task<bool> Save()
        {
            try { await store.SaveAsync(new() { Targets = [Target()] }, 0); return true; }
            catch (SyslogSettingsConflictException) { return false; }
        }
        Assert.Single(await Task.WhenAll(Save(), Save()), value => value);
        var path = Path.Combine(configuration["Honeypot:DataDirectory"]!, "syslog", "settings.json");
        await File.WriteAllTextAsync(path, "synthetic-corrupt-settings");
        var broken = new FileSyslogSettingsStore(configuration, new TestEnvironment());
        Assert.False(broken.Current.Settings.Enabled);
        Assert.Equal("SYSLOG_CONFIGURATION_UNAVAILABLE", broken.Current.ConfigFault);
        await Assert.ThrowsAsync<SyslogSettingsUnavailableException>(() => broken.SaveAsync(new(), 0));
        Assert.Equal("synthetic-corrupt-settings", await File.ReadAllTextAsync(path));
    }

    [Fact]
    public void ValidationResetsTlsBypassAndRejectsUnsafeOrAmbiguousTargets()
    {
        Assert.True(SyslogSettingsValidation.TryNormalize(new() { Targets = [Target() with { Protocol = SyslogProtocol.Tcp, IgnoreSslErrors = true, IgnoredSeverities = [4, 4, 7] }] }, out var normalized));
        Assert.False(normalized.Targets[0].IgnoreSslErrors);
        Assert.Empty(normalized.Targets[0].IgnoredSeverities!);
        foreach (var invalid in new[]
        {
            Target() with { Host = "https://example.invalid/path" }, Target() with { Host = "user@example.invalid" },
            Target() with { Host = "host\r\nforged" }, Target() with { Port = 0 },
            Target() with { Protocol = (SyslogProtocol)99 },
        }) Assert.False(SyslogSettingsValidation.TryNormalize(new() { Targets = [invalid] }, out _));
        Assert.False(SyslogSettingsValidation.TryNormalize(new() { Enabled = true }, out _));
        Assert.False(SyslogSettingsValidation.TryNormalize(new() { Targets = [Target(), Target()] }, out _));
    }

    [Fact]
    public async Task EndpointsEnforceRolesVersionsAndTelemetryAllowlist()
    {
        await using var fixture = await Fixture.Start();
        var client = fixture.Client;
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/api/v1/settings/syslog")).StatusCode);
        client.DefaultRequestHeaders.Add("X-Test-Role", "viewer");
        Assert.Equal(HttpStatusCode.Forbidden, (await client.GetAsync("/api/v1/settings/syslog")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await client.PostAsJsonAsync("/api/v1/syslog/test", new SyslogTestRequest("target-1"))).StatusCode);
        var diagnostic = await client.PostAsJsonAsync("/api/v1/telemetry/frontend-logs", new FrontendDiagnosticRequest("UI_UNHANDLED_ERROR", "credentials"));
        Assert.Equal(HttpStatusCode.OK, diagnostic.StatusCode);
        var log = Assert.Single(fixture.Publisher.Items);
        Assert.Equal(SyslogSeverity.Error, log.Severity);
        foreach (var body in new[]
        {
            "{\"eventCode\":\"UI_UNHANDLED_ERROR\",\"routeKey\":\"credentials\",\"message\":\"synthetic-secret\"}",
            "{\"eventCode\":\"UI_UNHANDLED_ERROR\",\"routeKey\":\"credentials\",\"severity\":0}",
            "{\"eventCode\":\"UI_UNHANDLED_ERROR\",\"routeKey\":\"/credentials?token=synthetic-secret\"}",
            new string('x', 17000),
        })
        {
            var rejected = await client.PostAsync("/api/v1/telemetry/frontend-logs", new StringContent(body, Encoding.UTF8, "application/json"));
            Assert.Equal(HttpStatusCode.BadRequest, rejected.StatusCode);
            Assert.DoesNotContain("synthetic-secret", await rejected.Content.ReadAsStringAsync());
        }
        Assert.Single(fixture.Publisher.Items);
        client.DefaultRequestHeaders.Remove("X-Test-Role");
        client.DefaultRequestHeaders.Add("X-Test-Role", "Administrator");
        var settings = new SyslogSettings { Targets = [Target()] };
        var saved = await client.PutAsJsonAsync("/api/v1/settings/syslog", new UpdateSyslogSettingsRequest(settings, 0));
        Assert.Equal(HttpStatusCode.OK, saved.StatusCode);
        Assert.True(saved.Headers.CacheControl?.NoStore);
        Assert.Equal(HttpStatusCode.Conflict, (await client.PutAsJsonAsync("/api/v1/settings/syslog", new UpdateSyslogSettingsRequest(settings, 0))).StatusCode);
        foreach (var invalidMessage in new[] { "line\nbreak", new string('x', SyslogTestRequest.MaximumMessageLength + 1) })
            Assert.Equal(HttpStatusCode.BadRequest, (await client.PostAsJsonAsync("/api/v1/syslog/test", new SyslogTestRequest("target-1", invalidMessage))).StatusCode);
        Assert.Equal(0, fixture.Delivery.Tests);
        Assert.Equal(HttpStatusCode.OK, (await client.PostAsJsonAsync("/api/v1/syslog/test", new SyslogTestRequest("target-1", "  自定义测试消息  "))).StatusCode);
        Assert.Equal(1, fixture.Delivery.Tests);
        Assert.Equal("自定义测试消息", fixture.Delivery.LastMessage);
    }

    [Fact]
    public async Task TelemetryIsRateLimitedWithoutRecursiveDiagnostics()
    {
        await using var fixture = await Fixture.Start();
        fixture.Client.DefaultRequestHeaders.Add("X-Test-Role", "viewer");
        for (var index = 0; index < 30; index++)
            Assert.Equal(HttpStatusCode.OK, (await fixture.Client.PostAsJsonAsync("/api/v1/telemetry/frontend-logs", new FrontendDiagnosticRequest("UI_REQUEST_FAILED", "system", 503))).StatusCode);
        Assert.Equal(HttpStatusCode.TooManyRequests, (await fixture.Client.PostAsJsonAsync("/api/v1/telemetry/frontend-logs", new FrontendDiagnosticRequest("UI_REQUEST_FAILED", "system", 503))).StatusCode);
        Assert.Equal(30, fixture.Publisher.Items.Count);
    }

    private static SyslogTarget Target() => new("target-1", "Synthetic target", "syslog.example.invalid", 6514, SyslogProtocol.Tls);
    private static (FileSyslogSettingsStore, IConfiguration) NewStore()
    {
        var directory = Path.Combine(Path.GetTempPath(), "honeypot-syslog-settings-" + Guid.NewGuid().ToString("N"));
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["Honeypot:DataDirectory"] = directory }).Build();
        return (new(configuration, new TestEnvironment()), configuration);
    }
    private sealed class TestEnvironment : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = "Test";
        public string ApplicationName { get; set; } = "Test";
        public string ContentRootPath { get; set; } = Path.GetTempPath();
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
    private sealed class Publisher : ISyslogPublisher
    {
        public List<(string Code, SyslogSeverity Severity)> Items { get; } = [];
        public void Publish(string appName, string eventCode, SyslogSeverity severity, IReadOnlyDictionary<string, object?>? fields = null) => Items.Add((eventCode, severity));
    }
    private sealed class Delivery : ISyslogDeliveryService
    {
        public int Tests;
        public string? LastMessage;
        public SyslogDeliveryStatus GetStatus() => new(false, "tongyan-honeypot-TEST", []);
        public Task<SyslogTestResult> TestAsync(string targetId, string? message = null, CancellationToken cancellationToken = default)
        { Tests++; LastMessage = message; return Task.FromResult(new SyslogTestResult(targetId, "test-id", true, "LocalSubmitted")); }
    }
    private sealed class Fixture(WebApplication app, HttpClient client, Publisher publisher, Delivery delivery) : IAsyncDisposable
    {
        public HttpClient Client => client;
        public Publisher Publisher => publisher;
        public Delivery Delivery => delivery;
        public static async Task<Fixture> Start()
        {
            var builder = WebApplication.CreateBuilder();
            builder.Logging.ClearProviders();
            builder.WebHost.UseUrls("http://127.0.0.1:0");
            var (settings, _) = NewStore();
            var publisher = new Publisher(); var delivery = new Delivery();
            builder.Services.AddSingleton<ISyslogSettingsStore>(settings);
            builder.Services.AddSingleton<ISyslogPublisher>(publisher);
            builder.Services.AddSingleton<ISyslogDeliveryService>(delivery);
            var app = builder.Build();
            var userId = Guid.NewGuid().ToString("N");
            app.Use((context, next) =>
            {
                if (context.Request.Headers["X-Test-Role"].FirstOrDefault() is { } role)
                    context.Items["CurrentUser"] = new AuthenticatedUser(userId, "test", [role]);
                return next(context);
            });
            app.MapSyslogEndpoints();
            await app.StartAsync();
            return new(app, new HttpClient { BaseAddress = new Uri(app.Urls.Single()) }, publisher, delivery);
        }
        public async ValueTask DisposeAsync() { client.Dispose(); await app.StopAsync(); await app.DisposeAsync(); }
    }
}
