using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Honeypot.Api.Common;
using Honeypot.Api.Data;
using Honeypot.Api.Middleware;
using Honeypot.Api.Models;
using Honeypot.Api.Options;
using Honeypot.Api.Service;
using Honeypot.Api.Service.impl;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Xunit;

namespace Honeypot.Runtime.Tests;

public sealed class ManagementOperationAuditTests
{
    private const string AuditPath = "/api/v1/management/audits";
    private const string SyntheticSecret = "test-secret-not-for-audit";

    [Fact]
    public async Task ReopenedHostReadsAuditsWithoutSyslogOrRequestData()
    {
        var directory = Directory.CreateTempSubdirectory("honeypot-management-audit-");
        var connection = new SqliteConnectionStringBuilder
            { DataSource = Path.Combine(directory.FullName, "audit.db"), Pooling = false }.ToString();
        var clock = new TestClock();
        await using (var app = await StartAsync(connection, clock))
        {
            using var admin = Client(app, "Administrator");
            using var initial = await admin.PutAsJsonAsync($"/api/v1/settings/notifications?parameter={SyntheticSecret}", new
            {
                authorizationCode = SyntheticSecret
            });
            Assert.Equal(HttpStatusCode.NoContent, initial.StatusCode);
            var store = app.Services.GetRequiredService<ManagementOperationAuditStore>();
            await store.BeginAsync("AdminInitialize", null, default);
            clock.Advance(TimeSpan.FromHours(1));
            await store.BeginAsync("AdminLogout", null, default);
            clock.Advance(TimeSpan.FromDays(90) - TimeSpan.FromMinutes(30));
            using var instanceRequest = new HttpRequestMessage(HttpMethod.Post, $"/api/v1/service-instances/{SyntheticSecret}/start");
            instanceRequest.Headers.Add("X-Synthetic-Lowercase-Method", "1");
            using var limited = await admin.SendAsync(instanceRequest);
            Assert.Equal(HttpStatusCode.Conflict, limited.StatusCode);
            clock.Advance(TimeSpan.FromSeconds(1));
            using var login = await admin.PostAsJsonAsync("/api/v1/auth/login", new { password = SyntheticSecret });
            Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        }

        // 使用同一个磁盘文件重建宿主，不注册 Syslog。
        await using var reopened = await StartAsync(connection, clock, initialize: false);
        using var anonymous = Client(reopened);
        using var viewer = Client(reopened, "Viewer");
        using var administrator = Client(reopened, "Administrator");
        using var denied = await anonymous.GetAsync(AuditPath);
        using var forbidden = await viewer.GetAsync(AuditPath + "?page=invalid");
        Assert.Equal(HttpStatusCode.Unauthorized, denied.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, forbidden.StatusCode);
        using var invalid = await administrator.GetAsync(AuditPath + "?pageSize=101");
        Assert.Equal(HttpStatusCode.BadRequest, invalid.StatusCode);

        var first = await ReadPageAsync(administrator, page: 1);
        var second = await ReadPageAsync(administrator, page: 2);
        Assert.Equal(3, first.GetProperty("total").GetInt32());
        Assert.Equal(1, first.GetProperty("page").GetInt32());
        var items = first.GetProperty("items").EnumerateArray().Concat(second.GetProperty("items").EnumerateArray()).ToArray();
        Assert.Collection(items,
            item => AssertAudit(item, "AdminLogin", "Completed", 200, "synthetic-logged-in-user"),
            item => AssertAudit(item, "ServiceInstanceStart", "Completed", 409, "synthetic-existing-user", "verified-instance"),
            item => AssertAudit(item, "AdminLogout", "Unknown", null, null));
        Assert.DoesNotContain(SyntheticSecret,
            System.Text.Encoding.UTF8.GetString(await File.ReadAllBytesAsync(Path.Combine(directory.FullName, "audit.db"))));
    }

    [Fact]
    public async Task UnavailableAuditStorageRejectsOperationsBeforeBusinessHandlerRuns()
    {
        var directory = Directory.CreateTempSubdirectory("honeypot-management-audit-unavailable-");
        var connection = new SqliteConnectionStringBuilder
            { DataSource = Path.Combine(directory.FullName, "audit.db"), Pooling = false }.ToString();
        var invoked = false;
        await using var app = await StartAsync(connection, new TestClock(), initialize: false, onMutation: () => invoked = true,
            identityInitialized: false);
        using var admin = Client(app, "Administrator");
        using var result = await admin.PutAsync("/api/v1/settings/notifications", null);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, result.StatusCode);
        Assert.False(invoked);
        using var setup = await admin.PostAsync("/api/v1/setup/initialize?complete=true", null);
        Assert.Equal(HttpStatusCode.OK, setup.StatusCode);
    }

    [Fact]
    public async Task EveryFailedLoginIsAuditedWithoutChangingAuthenticationResults()
    {
        var directory = Directory.CreateTempSubdirectory("honeypot-management-audit-login-");
        var connection = new SqliteConnectionStringBuilder
            { DataSource = Path.Combine(directory.FullName, "audit.db"), Pooling = false }.ToString();
        await using var app = await StartAsync(connection, new TestClock());
        using var anonymous = Client(app);
        for (var attempt = 0; attempt < 20; attempt++)
        {
            using var denied = await anonymous.PostAsync("/api/v1/auth/login?syntheticStatus=401", null);
            Assert.Equal(HttpStatusCode.Unauthorized, denied.StatusCode);
            using var locked = await anonymous.PostAsync("/api/v1/auth/login?syntheticStatus=429", null);
            Assert.Equal(HttpStatusCode.TooManyRequests, locked.StatusCode);
            using var logout = await anonymous.PostAsync("/api/v1/auth/logout", null);
            Assert.Equal(HttpStatusCode.OK, logout.StatusCode);
        }
        using var lockoutStarted = await anonymous.PostAsync("/api/v1/auth/login?syntheticStatus=429&lockoutStarted=true", null);
        Assert.Equal(HttpStatusCode.TooManyRequests, lockoutStarted.StatusCode);
        using var administrator = Client(app, "Administrator");
        using var verifiedLogout = await administrator.PostAsync("/api/v1/auth/logout", null);
        Assert.Equal(HttpStatusCode.OK, verifiedLogout.StatusCode);
        var page = await ReadPageAsync(administrator, page: 1, pageSize: 50);
        Assert.Equal(42, page.GetProperty("total").GetInt32());
        var statuses = page.GetProperty("items").EnumerateArray().GroupBy(item => item.GetProperty("httpStatus").GetInt32())
            .ToDictionary(group => group.Key, group => group.ToArray());
        Assert.Equal(20, statuses[401].Length);
        Assert.All(statuses[401], item => AssertAudit(item, "AdminLogin", "Completed", 401, null));
        Assert.Equal(21, statuses[429].Length);
        Assert.All(statuses[429], item => AssertAudit(item, "AdminLogin", "Completed", 429, null));
        AssertAudit(Assert.Single(statuses[200]), "AdminLogout", "Completed", 200, "synthetic-existing-user");
    }

    [Fact]
    public async Task EveryFailedSetupIsAuditedWithoutBlockingInitialization()
    {
        var directory = Directory.CreateTempSubdirectory("honeypot-management-audit-setup-");
        var connection = new SqliteConnectionStringBuilder
            { DataSource = Path.Combine(directory.FullName, "audit.db"), Pooling = false }.ToString();
        await using var app = await StartAsync(connection, new TestClock(), identityInitialized: false);
        using var anonymous = Client(app);
        for (var attempt = 0; attempt < 20; attempt++)
        {
            using var failed = await anonymous.PostAsync("/api/v1/setup/initialize", null);
            Assert.Equal(HttpStatusCode.BadRequest, failed.StatusCode);
        }

        using var succeeded = await anonymous.PostAsync("/api/v1/setup/initialize?complete=true", null);
        Assert.Equal(HttpStatusCode.OK, succeeded.StatusCode);
        using var administrator = Client(app, "Administrator");
        var page = await ReadPageAsync(administrator, page: 1, pageSize: 50);
        Assert.Equal(21, page.GetProperty("total").GetInt32());
        var results = page.GetProperty("items").EnumerateArray().ToArray();
        AssertAudit(Assert.Single(results, item => item.GetProperty("httpStatus").GetInt32() == 200),
            "AdminInitialize", "Completed", 200, "synthetic-initialized-user", "synthetic-initialized-user");
        Assert.All(results.Where(item => item.GetProperty("httpStatus").GetInt32() != 200),
            item => AssertAudit(item, "AdminInitialize", "Completed", 400, null));
    }

    private static void AssertAudit(JsonElement item, string operation, string state, int? status, string? actor,
        string? resource = null)
    {
        Assert.Equal(operation, item.GetProperty("operation").GetString());
        Assert.Equal(state, item.GetProperty("state").GetString());
        var statusField = item.GetProperty("httpStatus");
        Assert.Equal(status, statusField.ValueKind == JsonValueKind.Null ? (int?)null : statusField.GetInt32());
        Assert.Equal(actor, item.GetProperty("actorUserId").GetString());
        Assert.Equal(resource, item.GetProperty("resourceId").GetString());
    }

    private static async Task<JsonElement> ReadPageAsync(HttpClient client, int page, int pageSize = 2)
    {
        using var response = await client.GetAsync($"{AuditPath}?page={page}&pageSize={pageSize}");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(response.Headers.CacheControl?.NoStore);
        var body = await response.Content.ReadAsStringAsync();
        Assert.DoesNotContain(SyntheticSecret, body, StringComparison.Ordinal);
        using var json = JsonDocument.Parse(body);
        return json.RootElement.GetProperty("data").Clone();
    }

    private static HttpClient Client(WebApplication app, string? role = null)
    {
        var client = new HttpClient(new HttpClientHandler { UseProxy = false })
            { BaseAddress = new Uri(Assert.Single(app.Urls)) };
        if (role is not null) client.DefaultRequestHeaders.Add("X-Synthetic-Role", role);
        return client;
    }

    private static async Task<WebApplication> StartAsync(string connection, TestClock clock, bool initialize = true,
        Action? onMutation = null, bool identityInitialized = true)
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(settings => settings.Listen(IPAddress.Loopback, 0));
        builder.Services.AddDbContextFactory<HoneypotDbContext>(options => options.UseSqlite(connection));
        builder.Services.AddSingleton<IResourceIdGenerator, ResourceIdGenerator>();
        builder.Services.AddSingleton<IUserIdentityService>(new TestIdentity(identityInitialized));
        builder.Services.AddSingleton<TimeProvider>(clock);
        builder.Services.AddOptions<EventStorageOptions>();
        builder.Services.AddSingleton<ManagementOperationAuditStore>();
        var app = builder.Build();
        if (initialize)
        {
            await using var db = await app.Services.GetRequiredService<IDbContextFactory<HoneypotDbContext>>().CreateDbContextAsync();
            await db.Database.EnsureCreatedAsync();
        }

        app.Use(async (context, next) =>
        {
            if (context.Request.Headers.TryGetValue("X-Synthetic-Role", out var role))
                context.Items["CurrentUser"] = new AuthenticatedUser("synthetic-existing-user", "synthetic-user", [role.ToString()]);
            if (context.Request.Headers.ContainsKey("X-Synthetic-Lowercase-Method"))
                context.Request.Method = context.Request.Method.ToLowerInvariant();
            await next();
        });
        app.UseMiddleware<ManagementOperationAuditMiddleware>();
        app.MapManagementOperationAuditEndpoints();
        app.MapPut("/api/v1/settings/notifications", () =>
        {
            onMutation?.Invoke();
            return Results.NoContent();
        });
        app.MapPost("/api/v1/service-instances/{instanceId}/start", (HttpContext context) =>
        {
            ManagementOperationAuditMiddleware.SetResourceId(context, "verified-instance");
            return Results.Conflict();
        });
        app.MapPost("/api/v1/auth/login", (HttpContext context) =>
        {
            if (int.TryParse(context.Request.Query["syntheticStatus"], out var status))
            {
                if (context.Request.Query["lockoutStarted"] == "true")
                    ManagementOperationAuditMiddleware.MarkLoginLockoutStarted(context);
                return Results.StatusCode(status);
            }
            context.Items["CurrentUser"] = new AuthenticatedUser("synthetic-logged-in-user", "synthetic-user", ["Administrator"]);
            return Results.Ok();
        });
        app.MapPost("/api/v1/auth/logout", () => Results.Ok());
        app.MapPost("/api/v1/setup/initialize", (HttpContext context) =>
        {
            if (context.Request.Query["complete"] != "true") return Results.BadRequest();
            context.Items["CurrentUser"] = new AuthenticatedUser("synthetic-initialized-user", "synthetic-user", ["Administrator"]);
            ManagementOperationAuditMiddleware.SetResourceId(context, "synthetic-initialized-user");
            return Results.Ok();
        });
        await app.StartAsync();
        return app;
    }

    private sealed class TestClock : TimeProvider
    {
        private DateTimeOffset _now = new(2026, 11, 15, 0, 0, 0, TimeSpan.Zero);
        public override DateTimeOffset GetUtcNow() => _now;
        public void Advance(TimeSpan duration) => _now += duration;
    }

    private sealed class TestIdentity(bool initialized) : IUserIdentityService
    {
        public bool IsInitialized => initialized;

        public Task<(bool Succeeded, string Code, string Message)> InitializeFirstAdminAsync(string username, string password,
            CancellationToken cancellationToken = default) => throw new NotSupportedException();

        public Task<LoginAttemptResult> LoginAsync(string? username, string? password, CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public bool TryAuthenticate(string accessToken, out AuthenticatedUser? user) => throw new NotSupportedException();
        public void Logout(string accessToken) => throw new NotSupportedException();
        public IReadOnlyCollection<AuthenticatedUser> GetUsers() => throw new NotSupportedException();
    }
}
