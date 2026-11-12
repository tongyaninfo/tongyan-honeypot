using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Honeypot.Api.Common;
using Honeypot.Api.Data;
using Honeypot.Api.Models;
using Honeypot.Api.Service;
using Honeypot.Api.Service.impl;
using Honeypot.Api.Workers;
using Honeypot.Engine.Service;
using Honeypot.Engine.Service.impl;
using Honeypot.Protocol.Abstractions.Models;
using Honeypot.Protocol.Abstractions.Service;
using Honeypot.Runtime.Service;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using ModelContextProtocol.Client;
using Xunit;

namespace Honeypot.Runtime.Tests;

public sealed class McpTransportTests
{
    [Theory]
    [InlineData(false, "2025-11-25")]
    [InlineData(true, "2026-07-28")]
    public async Task OfficialClientListsAuthorizedToolsAndAuditsHttpAndHttps(bool https, string version)
    {
        await using var host = await Fixture.StartAsync(https);
        var key = await host.KeyAsync(McpAccess.ReadOnly, "preview_threat_decision");
        using var http = host.CreateClient(key.Secret);
        http.DefaultRequestHeaders.TryAddWithoutValidation("X-Call-Context", "evidence-review");
        http.DefaultRequestHeaders.TryAddWithoutValidation("Cookie", "mcp_test_session=isolated-placeholder");
        http.DefaultRequestHeaders.TryAddWithoutValidation("X-Forwarded-For", "192.0.2.99");

        await using var client = await host.ConnectAsync(http, version);
        Assert.Equal("preview_threat_decision", Assert.Single(await client.ListToolsAsync()).Name);
        var result = await client.CallToolAsync("preview_threat_decision", new Dictionary<string, object?>
        {
            ["sourceIp"] = "192.0.2.10", ["sensorType"] = "ssh", ["failedAttempts"] = 2, ["confidence"] = 0.5,
        });
        Assert.NotEqual(true, result.IsError);
        Assert.True(result.StructuredContent!.Value.GetProperty("success").GetBoolean());

        var denied = await client.CallToolAsync("start_service_instance", new Dictionary<string, object?> { ["instanceId"] = "synthetic-instance" });
        Assert.True(denied.IsError);
        Assert.Equal("TOOL_NOT_AUTHORIZED", denied.StructuredContent!.Value.GetProperty("code").GetString());

        var details = await host.WaitForAuditAsync("preview_threat_decision");
        Assert.Equal("127.0.0.1", details.SourceIp);
        Assert.Equal(version, details.ProtocolVersion);
        Assert.Equal("tools/call", details.McpMethod);
        Assert.Equal(McpAuditResult.Success, details.Result);
        Assert.Contains("evidence-review", details.RequestHeaders);
        Assert.Contains("192.0.2.10", details.RequestParams);
        Assert.Contains("decision", details.ResponseBody, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(key.Secret, details.RequestHeaders);
        Assert.DoesNotContain(key.Secret, details.ResponseBody);
        Assert.DoesNotContain("isolated-placeholder", details.RequestHeaders);

        Assert.True(await host.Store.RevokeKeyAsync(key.Key.Id, default));
        using var request = Post(http.BaseAddress!);
        using var revoked = await http.SendAsync(request);
        Assert.Equal(HttpStatusCode.Unauthorized, revoked.StatusCode);
        Assert.Equal("OK", await host.Store.DeleteKeyAsync(key.Key.Id, default));
        Assert.Equal(key.Key.Id, (await host.WaitForAuditAsync("preview_threat_decision")).KeyId);
    }

    [Fact]
    public async Task DisabledAndExpiredKeysAreDeniedAndInvalidOriginIsRejected()
    {
        await using var host = await Fixture.StartAsync(https: false);
        var expired = await host.Store.CreateKeyAsync("expired-test", McpAccess.ReadOnly, ["get_overview"], [],
            DateTimeOffset.UtcNow.AddMinutes(-1), "test-admin", default);
        using var http = host.CreateClient(expired.Secret);
        using var old = Post(http.BaseAddress!);
        Assert.Equal(HttpStatusCode.Unauthorized, (await http.SendAsync(old)).StatusCode);
        using var differentOrigin = Post(http.BaseAddress!);
        differentOrigin.Headers.TryAddWithoutValidation("Origin", "https://unexpected.example.invalid");
        Assert.Equal(HttpStatusCode.Forbidden, (await http.SendAsync(differentOrigin)).StatusCode);
        using var bogusHost = Post(http.BaseAddress!);
        bogusHost.Headers.Host = "unexpected.example.invalid";
        Assert.Equal(HttpStatusCode.Forbidden, (await http.SendAsync(bogusHost)).StatusCode);

        await host.Store.UpdateSettingsAsync(new(false, null), "test-admin", default);
        using var off = Post(http.BaseAddress!);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, (await http.SendAsync(off)).StatusCode);
    }

    [Fact]
    public async Task TrustedProxyProvidesSourceAndScheme()
    {
        await using var host = await Fixture.StartAsync(https: false, trustedProxy: true);
        var key = await host.KeyAsync(McpAccess.ReadOnly, "get_overview");
        using var http = host.CreateClient(key.Secret);
        http.DefaultRequestHeaders.TryAddWithoutValidation("X-Forwarded-For", "192.0.2.18");
        http.DefaultRequestHeaders.TryAddWithoutValidation("X-Forwarded-Proto", "https");
        http.DefaultRequestHeaders.TryAddWithoutValidation("Origin", $"https://127.0.0.1:{http.BaseAddress!.Port}");
        await using var client = await host.ConnectAsync(http, "2026-07-28");
        Assert.NotEqual(true, (await client.CallToolAsync("get_overview")).IsError);
        Assert.Equal("192.0.2.18", (await host.WaitForAuditAsync("get_overview")).SourceIp);
    }

    [Fact]
    public async Task FailedAuditRegistrationPreventsChangesToInstance()
    {
        await using var host = await Fixture.StartAsync(https: false, failBeginAudit: true);
        var instance = host.Instances.Upsert(new()
        {
            InstanceId = "isolated-test-instance",
            DisplayName = "Isolated test",
            AdapterKey = "ssh",
            Profile = new() { ProfileId = "isolated-test-profile", AdapterKey = "ssh" },
            Bindings = [new() { ListenerId = "isolated-test-listener", BindAddress = "127.0.0.1", Port = 2222 }],
        });
        var key = await host.Store.CreateKeyAsync("isolated-write-test", McpAccess.ReadWrite, ["set_service_restart_policy"],
            [new(instance.InstanceId, McpInstanceScope.BindingFingerprint(instance))], null, "test-admin", default);
        using var http = host.CreateClient(key.Secret);
        await using var client = await host.ConnectAsync(http, "2026-07-28");

        var result = await client.CallToolAsync("set_service_restart_policy", new Dictionary<string, object?>
        {
            ["instanceId"] = instance.InstanceId, ["autoStart"] = true,
        });
        Assert.True(result.IsError);
        Assert.Equal("AUDIT_UNAVAILABLE", result.StructuredContent!.Value.GetProperty("code").GetString());
        Assert.False(host.Instances.Get(instance.InstanceId)!.AutoStart);
        Assert.Equal(McpAuditResult.Unavailable, (await host.WaitForAuditAsync("set_service_restart_policy")).Result);
    }

    private static HttpRequestMessage Post(Uri address) => new(HttpMethod.Post, new Uri(address, "/mcp"))
    {
        Content = new StringContent("""{"jsonrpc":"2.0","id":1,"method":"tools/list"}""", Encoding.UTF8, "application/json"),
    };

    private sealed class Fixture(WebApplication app, X509Certificate2? certificate) : IAsyncDisposable
    {
        public SqliteMcpStore Store => app.Services.GetRequiredService<SqliteMcpStore>();
        public IServiceInstanceStore Instances => app.Services.GetRequiredService<IServiceInstanceStore>();

        public Task<McpCreatedKey> KeyAsync(string mode, params string[] permissions) =>
            Store.CreateKeyAsync("isolated-test", mode, permissions, [], null, "test-admin", default);

        public HttpClient CreateClient(string token)
        {
            var handler = new HttpClientHandler { UseProxy = false };
            if (certificate is not null)
                handler.ServerCertificateCustomValidationCallback = (_, serverCertificate, _, _) =>
                    serverCertificate?.GetCertHashString(HashAlgorithmName.SHA256) == certificate.GetCertHashString(HashAlgorithmName.SHA256);
            var client = new HttpClient(handler) { BaseAddress = new Uri(app.Urls.Single()), Timeout = TimeSpan.FromSeconds(10) };
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            return client;
        }

        public Task<McpClient> ConnectAsync(HttpClient http, string version) => McpClient.CreateAsync(
            new HttpClientTransport(new()
            {
                Endpoint = new Uri(http.BaseAddress!, "/mcp"),
                TransportMode = HttpTransportMode.StreamableHttp,
            }, http), new() { ProtocolVersion = version });

        public async Task<McpAuditDetails> WaitForAuditAsync(string tool)
        {
            using var limit = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            while (!limit.IsCancellationRequested)
            {
                var audits = await Store.GetAuditsAsync(new(1, 10, null, tool, null, null, null, null), limit.Token);
                var first = audits.Items.FirstOrDefault(item => item.Result != McpAuditResult.Pending);
                if (first is not null) return (await Store.GetAuditAsync(first.Id, limit.Token))!;
                await Task.Delay(25, limit.Token);
            }
            throw new InvalidOperationException("The expected MCP audit was not persisted.");
        }

        public static async Task<Fixture> StartAsync(bool https, bool trustedProxy = false, bool failBeginAudit = false)
        {
            var isolated = Directory.CreateTempSubdirectory("honeypot-mcp-transport-");
            var builder = WebApplication.CreateBuilder(new WebApplicationOptions
            {
                Args = ["--Honeypot:DataDirectory", isolated.FullName],
                ContentRootPath = isolated.FullName,
                EnvironmentName = "McpIntegration",
            });
            builder.Logging.ClearProviders();
            if (trustedProxy)
                builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["Honeypot:Mcp:TrustedProxies:0"] = "127.0.0.1",
                    ["Honeypot:Mcp:AllowedHosts:0"] = "127.0.0.1",
                });
            var certificate = https ? TestCertificate() : null;
            builder.WebHost.ConfigureKestrel(options => options.Listen(IPAddress.Loopback, 0, listen =>
            {
                if (certificate is not null) listen.UseHttps(certificate);
            }));

            builder.Services.AddDbContextFactory<HoneypotDbContext>(options =>
                options.UseSqlite($"Data Source={Path.Combine(isolated.FullName, "mcp-test.db")};Foreign Keys=True"));
            builder.Services.AddSingleton<IResourceIdGenerator, ResourceIdGenerator>();
            builder.Services.AddSingleton<IUserIdentityService, FileUserIdentityService>();
            builder.Services.AddSingleton<IThreatDecisionEngine, ThreatDecisionEngine>();
            builder.Services.AddSingleton<IThreatProfileStore, InMemoryThreatProfileStore>();
            builder.Services.AddSingleton<IInteractionEventStore, InMemoryInteractionEventStore>();
            builder.Services.AddSingleton<ICredentialEvidenceStore, InMemoryCredentialEvidenceStore>();
            builder.Services.AddSingleton<IServiceInstanceStore, SqliteServiceInstanceStore>();
            builder.Services.AddSingleton<IProtocolAdapterRegistry, ProtocolAdapterRegistry>();
            builder.Services.AddSingleton<ServiceInstanceOperations>();
            builder.Services.AddSingleton<ISyslogSettingsStore, FileSyslogSettingsStore>();
            builder.Services.AddSingleton<SyslogQueue>();
            builder.Services.AddSingleton<ISyslogDeliveryService, SyslogDeliveryWorker>();
            builder.Services.AddHoneypotRuntime();
            builder.Services.AddHoneypotReports();
            builder.Services.AddHoneypotNotifications();
            builder.Services.AddHoneypotRealtime();
            builder.Services.AddHoneypotMcpPersistence();
            if (failBeginAudit)
                builder.Services.AddSingleton<IMcpStore>(services =>
                    new FaultingAuditStore(services.GetRequiredService<SqliteMcpStore>()));
            builder.Services.AddHoneypotMcpTransport(builder.Configuration);

            var app = builder.Build();
            try
            {
                await using (var db = await app.Services.GetRequiredService<IDbContextFactory<HoneypotDbContext>>().CreateDbContextAsync())
                    await db.Database.MigrateAsync();
                var identity = app.Services.GetRequiredService<IUserIdentityService>();
                var setup = await identity.InitializeFirstAdminAsync("isolated-admin", "Mcp_Test_Secret_2026!");
                Assert.True(setup.Succeeded);
                var fixture = new Fixture(app, certificate);
                await fixture.Store.UpdateSettingsAsync(new(true, null), "test-admin", default);
                app.UseHoneypotMcpTransport();
                app.MapHoneypotMcpTransport();
                await app.StartAsync();
                return fixture;
            }
            catch
            {
                await app.DisposeAsync();
                certificate?.Dispose();
                throw;
            }
        }

        private static X509Certificate2 TestCertificate()
        {
            using var key = RSA.Create(2048);
            var request = new CertificateRequest("CN=127.0.0.1", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var names = new SubjectAlternativeNameBuilder();
            names.AddIpAddress(IPAddress.Loopback);
            request.CertificateExtensions.Add(names.Build());
            return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddHours(1));
        }

        public async ValueTask DisposeAsync()
        {
            await app.StopAsync();
            await app.DisposeAsync();
            certificate?.Dispose();
        }
    }

    private sealed class FaultingAuditStore(SqliteMcpStore inner) : IMcpStore
    {
        public Task<McpSettings> GetSettingsAsync(CancellationToken cancellationToken) => inner.GetSettingsAsync(cancellationToken);
        public Task<McpAuthenticationResult> AuthenticateAsync(string token, CancellationToken cancellationToken) =>
            inner.AuthenticateAsync(token, cancellationToken);
        public Task TouchKeyAsync(string id, CancellationToken cancellationToken) => inner.TouchKeyAsync(id, cancellationToken);
        public Task<string> BeginAuditAsync(McpAuditEntry entry, CancellationToken cancellationToken) =>
            Task.FromException<string>(new InvalidOperationException("Synthetic audit storage failure."));
        public Task CompleteAuditAsync(string id, McpAuditEntry entry, CancellationToken cancellationToken) =>
            inner.CompleteAuditAsync(id, entry, cancellationToken);
        public Task RecordAuditAsync(McpAuditEntry entry, CancellationToken cancellationToken) =>
            inner.RecordAuditAsync(entry, cancellationToken);
    }
}
