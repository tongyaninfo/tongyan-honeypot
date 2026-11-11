using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Honeypot.Api.Common;
using Honeypot.Api.Models;
using Honeypot.Api.Service;
using Honeypot.Api.Service.impl;
using Honeypot.Engine.Service.impl;
using Honeypot.Protocol.Abstractions.Models;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Xunit;

namespace Honeypot.Runtime.Tests;

public sealed class CredentialEvidenceTests
{
    [Theory]
    [InlineData("Administrator", true)]
    [InlineData("administrator", true)]
    [InlineData("ADMIN", true)]
    [InlineData("Analyst", false)]
    [InlineData("viewer", false)]
    public void EvidenceAuthorizationUsesRealIdentityRoles(string role, bool allowed)
    {
        Assert.Equal(allowed, UserAuthorization.IsAdministrator(new("test-user", "test-user", new[] { role })));
        Assert.False(UserAuthorization.IsAdministrator(null));
    }

    [Theory]
    [InlineData("GET", "/api/v1/credential-evidence/cred-example", "Read", "cred-example")]
    [InlineData("POST", "/api/v1/credential-evidence/export", "Export", "")]
    public void AuthenticationMiddlewareRejectionAlsoAuditsEvidenceAccess(string method, string path, string operation, string artifactId)
    {
        using var services = new ServiceCollection()
            .AddSingleton<ICredentialEvidenceStore, InMemoryCredentialEvidenceStore>()
            .AddSingleton<ICredentialEvidenceAccessService, CredentialEvidenceAccessService>()
            .BuildServiceProvider();
        var context = new DefaultHttpContext { RequestServices = services };
        context.Request.Method = method;
        context.Request.Path = path;
        context.Request.Headers.Authorization = "Bearer isolated-test-token";
        CredentialEvidenceEndpoints.AuditUnauthenticatedRead(context);
        var audit = Assert.Single(services.GetRequiredService<ICredentialEvidenceAccessService>().GetAuditTrail());
        Assert.Equal("UNAUTHORIZED", audit.Outcome);
        Assert.Equal(operation, audit.Operation);
        Assert.Equal(artifactId, audit.CredentialArtifactId);
        Assert.Null(audit.UserId);
        Assert.DoesNotContain("isolated-test-token", JsonSerializer.Serialize(audit));
    }

    [Fact]
    public async Task EncryptedEvidenceRoundTripsAndExpires()
    {
        var clock = new TestClock();
        using var store = new InMemoryCredentialEvidenceStore(clock);
        var saved = await Save(store);
        Assert.Equal("{\"password\":\"isolated-sample-password\"}", store.Get(saved.CredentialArtifactId)!.Content);
        Assert.DoesNotContain("isolated-sample-password", JsonSerializer.Serialize(store.GetAll()));
        clock.Advance(TimeSpan.FromDays(1));
        Assert.Null(store.Get(saved.CredentialArtifactId));
        Assert.Empty(store.GetAll());
    }

    [Fact]
    public async Task AccessRequiresAdminAndAuditsBothAllowedAndDeniedReads()
    {
        using var store = new InMemoryCredentialEvidenceStore();
        var saved = await Save(store);
        var access = new CredentialEvidenceAccessService(store);
        Assert.Equal(401, access.Read(saved.CredentialArtifactId, null).StatusCode);
        Assert.Equal(403, access.Read(saved.CredentialArtifactId, new("viewer", "viewer", new[] { "viewer" })).StatusCode);
        Assert.Equal(200, access.Read(saved.CredentialArtifactId, new("admin", "admin", new[] { "admin" })).StatusCode);
        Assert.Equal(404, access.Read("missing", new("admin", "admin", new[] { "admin" })).StatusCode);
        Assert.Equal(4, access.GetAuditTrail().Count);
        Assert.DoesNotContain("isolated-sample-password", JsonSerializer.Serialize(access.GetAuditTrail()));
    }

    [Fact]
    public async Task OrdinaryEventStoreAndRealtimeDiscardLegacyPassword()
    {
        using var evidence = new InMemoryCredentialEvidenceStore();
        var store = new InMemoryInteractionEventStore(new InMemoryThreatProfileStore(), evidence);
        var item = new InteractionEvent { EventId = "evt", ConnectionId = "conn", EventType = "AuthenticationAttempted",
            SourceIp = "192.0.2.10", DestinationIp = "127.0.0.1", ListenerId = "listener", ServiceInstanceId = "instance",
            AdapterKey = "ssh", ProfileId = "profile", Password = "isolated-sample-password", Outcome = "failure",
            AuthenticationMethod = "password", AuthenticationFailureCode = "AUTH_FAILED", MaterialType = "Plaintext" };
        await store.AppendAsync(item);
        Assert.Null(Assert.Single(store.GetAll()).Password);
        Assert.DoesNotContain("isolated-sample-password", JsonSerializer.Serialize(store.GetByConnectionId("conn")));
        var realtime = RealtimeInteractionEvent.From(item);
        Assert.Equal("password", realtime.AuthenticationMethod);
        Assert.DoesNotContain("isolated-sample-password", JsonSerializer.Serialize(realtime));
    }

    [Fact]
    public async Task EvidenceHttpRoutesIgnoreSelfDeclaredPermissionAndReturnApiResult()
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        builder.Logging.ClearProviders();
        // 使用隔离目录中的真实初始化与登录链路，避免测试虚构角色而漏掉生产身份合同。
        builder.Configuration["Honeypot:DataDirectory"] = Path.Combine(Path.GetTempPath(), $"honeypot-evidence-identity-{Guid.NewGuid():N}");
        var clock = new TestClock();
        builder.Services.AddSingleton<TimeProvider>(clock);
        builder.Services.AddSingleton<IUserIdentityService, FileUserIdentityService>();
        builder.Services.AddSingleton<ICredentialEvidenceStore, InMemoryCredentialEvidenceStore>();
        builder.Services.AddSingleton<ICredentialEvidenceAccessService, CredentialEvidenceAccessService>();
        await using var app = builder.Build();
        var identity = app.Services.GetRequiredService<IUserIdentityService>();
        Assert.True((await identity.InitializeFirstAdminAsync("isolated-admin", "Isolated-test-Password123!")).Succeeded);
        var login = await identity.LoginAsync("isolated-admin", "Isolated-test-Password123!");
        Assert.NotNull(login);
        Assert.Contains("Administrator", login.User.Roles);
        // 未授权/分析员场景注入受限测试身份；管理员使用真实登录令牌，不接触 SQLite/真实用户文件。
        app.Use(async (context, next) =>
        {
            var authorization = context.Request.Headers.Authorization.ToString();
            if (authorization.StartsWith("Bearer ", StringComparison.Ordinal) && identity.TryAuthenticate(authorization[7..], out var user))
                context.Items["CurrentUser"] = user;
            else if (context.Request.Headers.TryGetValue("X-Test-Role", out var role))
                context.Items["CurrentUser"] = new AuthenticatedUser("test-user", "test-user", new[] { role.ToString() });
            await next();
        });
        app.MapCredentialEvidenceEndpoints();
        await app.StartAsync();
        try
        {
            var store = app.Services.GetRequiredService<ICredentialEvidenceStore>();
            var expired = await Save(store);
            clock.Advance(TimeSpan.FromDays(1));
            var saved = await Save(store);
            const string exportPath = "/api/v1/credential-evidence/export";
            var exportRequest = new { artifactIds = new[] { expired.CredentialArtifactId, saved.CredentialArtifactId } };
            using var client = new HttpClient { BaseAddress = new Uri(Assert.Single(app.Urls)) };
            client.DefaultRequestHeaders.Add("X-Honeypot-Evidence-Read", "true");
            var unauthorized = await client.GetAsync($"/api/v1/credential-evidence/{saved.CredentialArtifactId}");
            Assert.Equal(HttpStatusCode.Unauthorized, unauthorized.StatusCode);
            using var unauthorizedExport = await client.PostAsJsonAsync(exportPath, exportRequest);
            Assert.Equal(HttpStatusCode.Unauthorized, unauthorizedExport.StatusCode);
            Assert.DoesNotContain("isolated-sample-password", await unauthorizedExport.Content.ReadAsStringAsync());
            client.DefaultRequestHeaders.Add("X-Test-Role", "viewer");
            var forbidden = await client.GetAsync($"/api/v1/credential-evidence/{saved.CredentialArtifactId}");
            Assert.Equal(HttpStatusCode.Forbidden, forbidden.StatusCode);
            Assert.Contains("\"success\":false", await forbidden.Content.ReadAsStringAsync());
            using var forbiddenExport = await client.PostAsJsonAsync(exportPath, exportRequest);
            Assert.Equal(HttpStatusCode.Forbidden, forbiddenExport.StatusCode);
            Assert.True(forbiddenExport.Headers.CacheControl!.NoStore);
            Assert.DoesNotContain("isolated-sample-password", await forbiddenExport.Content.ReadAsStringAsync());
            var summaries = await client.GetStringAsync("/api/v1/credential-evidence");
            Assert.Contains(saved.CredentialArtifactId, summaries);
            Assert.DoesNotContain("isolated-sample-password", summaries);
            client.DefaultRequestHeaders.Remove("X-Test-Role");
            client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", login.AccessToken);
            var allowed = await client.GetAsync($"/api/v1/credential-evidence/{saved.CredentialArtifactId}");
            Assert.Equal(HttpStatusCode.OK, allowed.StatusCode);
            Assert.True(allowed.Headers.CacheControl!.NoStore);
            Assert.Contains("isolated-sample-password", await allowed.Content.ReadAsStringAsync());

            foreach (var invalidIds in new string?[][]
            {
                [], [null], ["wrong-format"], ["cred-" + new string('a', 33)],
                [saved.CredentialArtifactId, saved.CredentialArtifactId.ToUpperInvariant()],
                Enumerable.Range(0, 9).Select(_ => $"cred-{Guid.NewGuid():N}").ToArray()
            })
            {
                using var invalidExport = await client.PostAsJsonAsync(exportPath, new { artifactIds = invalidIds });
                Assert.Equal(HttpStatusCode.BadRequest, invalidExport.StatusCode);
                Assert.Contains("INVALID_EXPORT_REQUEST", await invalidExport.Content.ReadAsStringAsync());
            }

            using var allowedExport = await client.PostAsJsonAsync(exportPath, exportRequest);
            Assert.Equal(HttpStatusCode.OK, allowedExport.StatusCode);
            Assert.True(allowedExport.Headers.CacheControl!.NoStore);
            using var exportJson = JsonDocument.Parse(await allowedExport.Content.ReadAsStringAsync());
            var items = exportJson.RootElement.GetProperty("data").GetProperty("items");
            Assert.Equal(2, items.GetArrayLength());
            Assert.Equal(expired.CredentialArtifactId, items[0].GetProperty("artifactId").GetString());
            Assert.Equal("NOT_FOUND_OR_EXPIRED", items[0].GetProperty("outcome").GetString());
            Assert.False(items[0].TryGetProperty("evidence", out _));
            Assert.Equal(saved.CredentialArtifactId, items[1].GetProperty("artifactId").GetString());
            Assert.Equal("OK", items[1].GetProperty("outcome").GetString());
            Assert.Contains("isolated-sample-password", items[1].GetProperty("evidence").GetProperty("content").GetString()!);

            var audit = await client.GetStringAsync("/api/v1/credential-evidence/audit");
            Assert.Contains("FORBIDDEN", audit);
            Assert.DoesNotContain("isolated-sample-password", audit);
            using var auditJson = JsonDocument.Parse(audit);
            var exportAudits = auditJson.RootElement.GetProperty("data").EnumerateArray()
                .Where(item => item.GetProperty("operation").GetString() == "Export").ToArray();
            Assert.Equal(4, exportAudits.Length);
            Assert.Contains(exportAudits, item => item.GetProperty("outcome").GetString() == "UNAUTHORIZED");
            Assert.Contains(exportAudits, item => item.GetProperty("outcome").GetString() == "FORBIDDEN");
            Assert.Contains(exportAudits, item => item.GetProperty("outcome").GetString() == "NOT_FOUND_OR_EXPIRED" &&
                item.GetProperty("credentialArtifactId").GetString() == expired.CredentialArtifactId);
            Assert.Contains(exportAudits, item => item.GetProperty("outcome").GetString() == "OK" &&
                item.GetProperty("credentialArtifactId").GetString() == saved.CredentialArtifactId &&
                item.GetProperty("userId").GetString() == login.User.UserId);
        }
        finally { await app.StopAsync(); }
    }

    private static Task<CredentialEvidenceSummary> Save(ICredentialEvidenceStore store) => store.SaveAsync(
        "conn", "event", "192.0.2.10", "ssh", "Plaintext", "{\"password\":\"isolated-sample-password\"}", 1);

    private sealed class TestClock : TimeProvider
    {
        private DateTimeOffset _utc = new(2026, 11, 9, 0, 0, 0, TimeSpan.Zero);
        public override DateTimeOffset GetUtcNow() => _utc;
        public void Advance(TimeSpan duration) => _utc += duration;
    }
}
