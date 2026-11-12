using System.Net;
using System.Net.Http.Json;
using Honeypot.Api.Common;
using Honeypot.Api.Data;
using Honeypot.Api.Models;
using Honeypot.Api.Service;
using Honeypot.Api.Service.impl;
using Honeypot.Protocol.Abstractions.Models;
using Honeypot.Shared.Models;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Xunit;

namespace Honeypot.Runtime.Tests;

public sealed class McpManagementTests
{
    private const string Management = "/api/v1/mcp";

    [Fact]
    public async Task ManagementRoutesEnforceAdministratorAndKeyIsReturnedOnlyOnCreate()
    {
        await using var host = await ManagementHost.StartAsync();
        using var anonymous = host.Client();
        using var member = host.Client("Member");
        using var admin = host.Client("Administrator");
        using var unauthenticated = await anonymous.GetAsync($"{Management}/keys");
        Assert.Equal(HttpStatusCode.Unauthorized, unauthenticated.StatusCode);
        using var forbidden = await member.GetAsync($"{Management}/audits");
        Assert.Equal(HttpStatusCode.Forbidden, forbidden.StatusCode);

        using var enabled = await admin.PutAsJsonAsync($"{Management}/settings", new { enabled = true });
        using var shortened = await admin.PutAsJsonAsync($"{Management}/settings", new { auditRetentionDays = 14 });
        var settings = await Read<McpSettings>(shortened);
        Assert.True(settings.Enabled);
        Assert.Equal(14, settings.AuditRetentionDays);
        Assert.True(enabled.Headers.CacheControl?.NoStore);

        var readOnly = new McpCreateKeyRequest("只读联调", McpAccess.ReadOnly, ["get_overview"], [], null);
        using var forbiddenTool = await admin.PostAsJsonAsync($"{Management}/keys",
            readOnly with { PermissionIds = ["start_service_instance"] });
        Assert.Equal(HttpStatusCode.BadRequest, forbiddenTool.StatusCode);
        using var ambiguousExpiry = await admin.PostAsJsonAsync($"{Management}/keys",
            readOnly with { ExpiresAtUtc = "2099-11-11T08:00:00" });
        Assert.Equal(HttpStatusCode.BadRequest, ambiguousExpiry.StatusCode);

        using var createdResponse = await admin.PostAsJsonAsync($"{Management}/keys", readOnly);
        Assert.Equal(HttpStatusCode.Created, createdResponse.StatusCode);
        Assert.True(createdResponse.Headers.CacheControl?.NoStore);
        var created = await Read<McpCreatedKey>(createdResponse);
        Assert.Null(created.Key.ExpiresAtUtc);
        using var keyList = await admin.GetAsync($"{Management}/keys");
        var listed = Assert.Single((await Read<McpPage<McpKeySummary>>(keyList)).Items);
        Assert.Equal(created.Key, listed with { PermissionIds = created.Key.PermissionIds, InstanceIds = created.Key.InstanceIds });
        Assert.Equal(readOnly.PermissionIds, listed.PermissionIds);
        Assert.DoesNotContain(created.Secret, await keyList.Content.ReadAsStringAsync());

        using var deleteBeforeRevoke = await admin.DeleteAsync($"{Management}/keys/{created.Key.Id}");
        Assert.Equal(HttpStatusCode.Conflict, deleteBeforeRevoke.StatusCode);
        using var revoke = await admin.PostAsync($"{Management}/keys/{created.Key.Id}/revoke", null);
        Assert.Equal(HttpStatusCode.OK, revoke.StatusCode);
        using var deleted = await admin.DeleteAsync($"{Management}/keys/{created.Key.Id}");
        Assert.Equal(HttpStatusCode.OK, deleted.StatusCode);
    }

    [Fact]
    public async Task InstanceWritePermissionRequiresExistingScopeAndFreezesItsBindingFingerprint()
    {
        await using var host = await ManagementHost.StartAsync();
        using var admin = host.Client("Administrator");
        using var permissionsResponse = await admin.GetAsync($"{Management}/permissions");
        var permissions = await Read<McpPermissions>(permissionsResponse);
        var instance = Assert.Single(permissions.Instances);
        var start = Assert.Single(permissions.Groups.SelectMany(group => group.Tools), tool => tool.Id == "start_service_instance");
        Assert.True(start.RequiresInstanceScope);
        Assert.Equal(McpAccess.ReadWrite, start.Access);

        var request = new McpCreateKeyRequest("实例联调", McpAccess.ReadWrite, [start.Id], [], null);
        using var missing = await admin.PostAsJsonAsync($"{Management}/keys", request);
        Assert.Equal(HttpStatusCode.BadRequest, missing.StatusCode);
        using var unknown = await admin.PostAsJsonAsync($"{Management}/keys", request with { InstanceIds = ["unknown"] });
        Assert.Equal(HttpStatusCode.BadRequest, unknown.StatusCode);
        using var createdResponse = await admin.PostAsJsonAsync($"{Management}/keys", request with { InstanceIds = [instance.Id] });
        var created = await Read<McpCreatedKey>(createdResponse);
        Assert.Equal(instance.Id, Assert.Single(created.Key.InstanceIds));
        var stored = (await host.Store.AuthenticateAsync(created.Secret)).Key;
        Assert.Equal(McpInstanceScope.BindingFingerprint(host.Instance), Assert.Single(stored!.InstanceGrants).BindingFingerprint);
    }

    private static async Task<T> Read<T>(HttpResponseMessage response)
    {
        response.EnsureSuccessStatusCode();
        var envelope = await response.Content.ReadFromJsonAsync<ApiResult<T>>();
        Assert.True(envelope?.Success);
        return envelope!.Data!;
    }

    private sealed class ManagementHost(WebApplication app, SqliteConnection anchor, ServiceInstance instance) : IAsyncDisposable
    {
        public ServiceInstance Instance => instance;
        public SqliteMcpStore Store => app.Services.GetRequiredService<SqliteMcpStore>();

        public HttpClient Client(string? role = null)
        {
            var client = new HttpClient(new HttpClientHandler { UseProxy = false })
                { BaseAddress = new Uri(app.Urls.Single()), Timeout = TimeSpan.FromSeconds(10) };
            if (role is not null) client.DefaultRequestHeaders.Add("X-Synthetic-Role", role);
            return client;
        }

        public static async Task<ManagementHost> StartAsync()
        {
            var connection = $"Data Source=mcp-management-{Guid.NewGuid():N};Mode=Memory;Cache=Shared;Pooling=False";
            var anchor = new SqliteConnection(connection);
            await anchor.OpenAsync();
            var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = "McpManagementTest" });
            builder.Logging.ClearProviders();
            builder.WebHost.ConfigureKestrel(options => options.Listen(IPAddress.Loopback, 0));
            builder.Services.AddDbContextFactory<HoneypotDbContext>(options => options.UseSqlite(connection));
            builder.Services.AddSingleton<IResourceIdGenerator, ResourceIdGenerator>();
            builder.Services.AddSingleton<ISyslogPublisher>(new NullSyslogPublisher());
            builder.Services.AddSingleton<IServiceInstanceStore, SqliteServiceInstanceStore>();
            builder.Services.AddHoneypotMcpPersistence();

            var app = builder.Build();
            try
            {
                await using (var db = await app.Services.GetRequiredService<IDbContextFactory<HoneypotDbContext>>().CreateDbContextAsync())
                    await db.Database.MigrateAsync();
                var instance = app.Services.GetRequiredService<IServiceInstanceStore>().Upsert(new()
                {
                    InstanceId = "synthetic-instance", DisplayName = "隔离实例", AdapterKey = "ssh",
                    Profile = new() { ProfileId = "synthetic-profile", AdapterKey = "ssh" },
                });
                // 模拟现有网页登录中间件已核验的身份，测试 MCP 管理路由本身的角色限制。
                app.Use(async (context, next) =>
                {
                    if (context.Request.Headers.TryGetValue("X-Synthetic-Role", out var role))
                        context.Items["CurrentUser"] = new AuthenticatedUser("synthetic-user", "synthetic-user", [role.ToString()]);
                    await next();
                });
                app.MapMcpManagementEndpoints();
                await app.StartAsync();
                return new(app, anchor, instance);
            }
            catch
            {
                await app.DisposeAsync();
                await anchor.DisposeAsync();
                throw;
            }
        }

        public async ValueTask DisposeAsync()
        {
            await app.DisposeAsync();
            await anchor.DisposeAsync();
        }
    }

    private sealed class NullSyslogPublisher : ISyslogPublisher
    {
        public void Publish(string appName, string eventCode, SyslogSeverity severity, IReadOnlyDictionary<string, object?>? fields = null) { }
    }
}
