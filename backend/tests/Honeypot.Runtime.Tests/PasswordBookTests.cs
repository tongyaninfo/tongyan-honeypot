using System.Net;
using System.Text.Json;
using Honeypot.Api.Common;
using Honeypot.Api.Models;
using Honeypot.Api.Service;
using Honeypot.Api.Service.impl;
using Honeypot.Engine.Service;
using Honeypot.Engine.Service.impl;
using Honeypot.Protocol.Abstractions.Models;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Xunit;

namespace Honeypot.Runtime.Tests;

public sealed class PasswordBookTests
{
    private const string Route = "/api/v1/password-book";
    private const string Account = "isolated-account";
    private const string Password = "Isolated-test-pass";

    [Fact]
    public async Task ListsGroupedAttemptsForAdministratorsAndKeepsPlaintextInAuditedEvidenceRoute()
    {
        var clock = new TestClock();
        await using var app = await StartAppAsync(clock);
        var first = await SaveAsync(app, "first", new { username = Account, password = Password });
        await AcceptAsync(app, first);
        clock.Advance(TimeSpan.FromMinutes(1));
        var differentPassword = await SaveAsync(app, "different-password", new { username = Account, password = Password + " " });
        await AcceptAsync(app, differentPassword);
        clock.Advance(TimeSpan.FromMinutes(1));
        var differentService = await SaveAsync(app, "different-service", new { username = Account, password = Password }, adapter: "telnet");
        await AcceptAsync(app, differentService);
        clock.Advance(TimeSpan.FromMinutes(1));
        var latest = await SaveAsync(app, "latest", new { username = Account, password = Password });
        await AcceptAsync(app, latest);

        using var client = new HttpClient { BaseAddress = new Uri(Assert.Single(app.Urls)) };
        client.DefaultRequestHeaders.Add("X-Honeypot-Evidence-Read", "true");
        using var unauthorized = await client.GetAsync(Route);
        Assert.Equal(HttpStatusCode.Unauthorized, unauthorized.StatusCode);
        client.DefaultRequestHeaders.Add("X-Test-Role", "Viewer");
        using var forbidden = await client.GetAsync(Route);
        Assert.Equal(HttpStatusCode.Forbidden, forbidden.StatusCode);
        client.DefaultRequestHeaders.Remove("X-Test-Role");
        client.DefaultRequestHeaders.Add("X-Test-Role", "Administrator");

        var page = await ReadPageAsync(client, pageSize: 2);
        Assert.Equal(3, page.GetProperty("total").GetInt32());
        Assert.Equal(1, page.GetProperty("page").GetInt32());
        Assert.Equal(2, page.GetProperty("pageSize").GetInt32());
        var rows = page.GetProperty("items");
        Assert.Equal(2, rows.GetArrayLength());
        Assert.Equal(Account, rows[0].GetProperty("username").GetString());
        Assert.Equal("ssh", rows[0].GetProperty("adapterKey").GetString());
        Assert.Equal(2, rows[0].GetProperty("authenticationCount").GetInt32());
        Assert.Equal(latest.OccurredAtUtc, rows[0].GetProperty("lastUsedAtUtc").GetDateTimeOffset());
        Assert.Equal(latest.CredentialArtifactId, rows[0].GetProperty("credentialArtifactId").GetString());
        Assert.Equal("telnet", rows[1].GetProperty("adapterKey").GetString());
        Assert.Equal(differentService.CredentialArtifactId, rows[1].GetProperty("credentialArtifactId").GetString());
        var pageTwo = await ReadPageAsync(client, page: 2, pageSize: 2);
        var remaining = Assert.Single(pageTwo.GetProperty("items").EnumerateArray());
        Assert.Equal(1, remaining.GetProperty("authenticationCount").GetInt32());
        Assert.Equal(differentPassword.CredentialArtifactId, remaining.GetProperty("credentialArtifactId").GetString());
        var audits = app.Services.GetRequiredService<ICredentialEvidenceAccessService>();
        Assert.DoesNotContain(audits.GetAuditTrail(), audit => audit.Operation == "Read");

        // 列表仅带证据引用，授权后读取单条原文继续经过既有取证审计。
        using var detail = await client.GetAsync($"/api/v1/credential-evidence/{latest.CredentialArtifactId}");
        Assert.Equal(HttpStatusCode.OK, detail.StatusCode);
        Assert.True(detail.Headers.CacheControl?.NoStore);
        using var response = JsonDocument.Parse(await detail.Content.ReadAsStringAsync());
        using var original = JsonDocument.Parse(response.RootElement.GetProperty("data").GetProperty("content").GetString()!);
        Assert.Equal(Password, original.RootElement.GetProperty("password").GetString());
        var readAudit = Assert.Single(audits.GetAuditTrail(), audit => audit.Operation == "Read");
        Assert.Equal("OK", readAudit.Outcome);
        Assert.Equal("isolated-admin", readAudit.UserId);
        Assert.Equal(latest.CredentialArtifactId, readAudit.CredentialArtifactId);
        Assert.DoesNotContain(Password, JsonSerializer.Serialize(readAudit));
    }

    [Fact]
    public async Task CountsOnlyConfirmedMatchingEventsAndEvictsExpiredAttemptsFromExistingGroup()
    {
        var clock = new TestClock();
        await using var app = await StartAppAsync(clock);
        using var client = CreateAdminClient(app);
        var first = await SaveAsync(app, "first", new { username = Account, password = Password });
        await AcceptAsync(app, first);
        var events = app.Services.GetRequiredService<InMemoryInteractionEventStore>();
        Assert.True((await events.AppendAsync(first)).IsDuplicate);

        await SaveAsync(app, "orphan", new { username = Account, password = Password });
        var wrongConnection = await SaveAsync(app, "wrong-connection", new { username = Account, password = Password });
        await AcceptAsync(app, wrongConnection with { ConnectionId = "mismatched-connection" });
        var wrongEvent = await SaveAsync(app, "original-event", new { username = Account, password = Password });
        await AcceptAsync(app, wrongEvent with { EventId = "mismatched-event" });

        clock.Advance(TimeSpan.FromMinutes(1));
        var current = await SaveAsync(app, "current", new { username = Account, password = Password }, retentionDays: 2);
        await AcceptAsync(app, current);
        var row = Assert.Single((await ReadPageAsync(client)).GetProperty("items").EnumerateArray());
        Assert.Equal(2, row.GetProperty("authenticationCount").GetInt32());

        clock.Advance(TimeSpan.FromDays(1));
        var surviving = Assert.Single((await ReadPageAsync(client)).GetProperty("items").EnumerateArray());
        Assert.Equal(1, surviving.GetProperty("authenticationCount").GetInt32());
        Assert.Equal(current.CredentialArtifactId, surviving.GetProperty("credentialArtifactId").GetString());

        clock.Advance(TimeSpan.FromDays(1));
        var expired = await ReadPageAsync(client);
        Assert.Equal(0, expired.GetProperty("total").GetInt32());
        Assert.Empty(expired.GetProperty("items").EnumerateArray());
    }

    [Fact]
    public async Task IncludesExplicitTextPasswordsAndExcludesMissingOrDerivedFields()
    {
        await using var app = await StartAppAsync(new TestClock());
        using var client = CreateAdminClient(app);
        var samples = new InteractionEvent[]
        {
            await SaveAsync(app, "missing-user", new { password = Password }),
            await SaveAsync(app, "missing-password", new { username = Account }),
            await SaveAsync(app, "nontext-secret", new { username = Account, password = (string?)null }),
            await SaveAsync(app, "response", new { username = Account, password = Password }, materialType: "Response"),
            (await SaveAsync(app, "account-disabled", new { username = Account, password = Password })) with { Username = null },
            await SaveAsync(app, "redis-derived", new { username = "default", password = Password, usernameProvided = false },
                adapter: "redis", method: "AUTH", username: "default"),
            await SaveAsync(app, "redis-legacy", new { username = "default", password = Password },
                adapter: "redis", method: "AUTH", username: "default"),
            await SaveAsync(app, "influx-missing-password", new { username = Account, password = "", passwordProvided = false },
                adapter: "influxdb", method: "HTTP-Query"),
            await SaveAsync(app, "influx-legacy", new { username = Account, password = "" }, adapter: "influxdb", method: "HTTP-Query"),
        };
        foreach (var sample in samples) await AcceptAsync(app, sample);
        Assert.Empty((await ReadPageAsync(client)).GetProperty("items").EnumerateArray());

        var submitted = new[]
        {
            await SaveAsync(app, "empty-password", new { username = Account, password = "" }),
            await SaveAsync(app, "redis-explicit", new { username = "default", password = Password, usernameProvided = true },
                adapter: "redis", method: "AUTH", username: "default"),
            await SaveAsync(app, "influx-explicit", new { username = Account, password = "", passwordProvided = true },
                adapter: "influxdb", method: "HTTP-Query"),
            await SaveAsync(app, "decrypted", new { username = Account, password = Password }, adapter: "mysql", materialType: "Decrypted"),
        };
        foreach (var item in submitted) await AcceptAsync(app, item);
        var visible = (await ReadPageAsync(client)).GetProperty("items").EnumerateArray()
            .Select(row => row.GetProperty("credentialArtifactId").GetString()).ToArray();
        Assert.Equal(submitted.Select(item => item.CredentialArtifactId).Order(), visible.Order());
    }

    [Fact]
    public async Task SearchesAccountOrServiceBeforePaginationWithoutReadingPasswords()
    {
        var clock = new TestClock();
        await using var app = await StartAppAsync(clock);
        using var client = CreateAdminClient(app);
        const string account = "运维Alpha%_one";
        await AcceptAsync(app, await SaveAsync(app, "repeated-start", new { username = account, password = Password }, username: account));
        clock.Advance(TimeSpan.FromMinutes(1));
        const string secondAccount = "运维Alpha%_two";
        var second = await SaveAsync(app, "second-match", new { username = secondAccount, password = Password }, username: secondAccount);
        await AcceptAsync(app, second);
        clock.Advance(TimeSpan.FromMinutes(1));
        var latest = await SaveAsync(app, "repeated-latest", new { username = account, password = Password }, username: account);
        await AcceptAsync(app, latest);
        clock.Advance(TimeSpan.FromMinutes(1));
        const string wildcardLookalike = "运维AlphaXY";
        var unmatched = await SaveAsync(app, "wildcard-lookalike", new { username = wildcardLookalike, password = Password },
            adapter: "redis", method: "AUTH", username: wildcardLookalike);
        await AcceptAsync(app, unmatched);

        const string keyword = "  运维aLPHa%_  ";
        var firstPage = await ReadPageAsync(client, pageSize: 1, keyword: keyword);
        Assert.Equal(2, firstPage.GetProperty("total").GetInt32());
        var firstRow = Assert.Single(firstPage.GetProperty("items").EnumerateArray());
        Assert.Equal(latest.CredentialArtifactId, firstRow.GetProperty("credentialArtifactId").GetString());
        Assert.Equal(2, firstRow.GetProperty("authenticationCount").GetInt32());
        var secondPage = await ReadPageAsync(client, page: 2, pageSize: 1, keyword: keyword);
        Assert.Equal(2, secondPage.GetProperty("total").GetInt32());
        Assert.Equal(second.CredentialArtifactId, Assert.Single(secondPage.GetProperty("items").EnumerateArray()).GetProperty("credentialArtifactId").GetString());
        var service = await ReadPageAsync(client, keyword: " eDI ");
        Assert.Equal(unmatched.CredentialArtifactId, Assert.Single(service.GetProperty("items").EnumerateArray()).GetProperty("credentialArtifactId").GetString());
        Assert.Equal(3, (await ReadPageAsync(client, keyword: "  ")).GetProperty("total").GetInt32());
        Assert.Equal(0, (await ReadPageAsync(client, keyword: Password)).GetProperty("total").GetInt32());
        Assert.Empty(app.Services.GetRequiredService<ICredentialEvidenceAccessService>().GetAuditTrail());

        using var oversized = await client.GetAsync($"{Route}?keyword={new string('x', 129)}");
        Assert.Equal(HttpStatusCode.BadRequest, oversized.StatusCode);
        Assert.True(oversized.Headers.CacheControl?.NoStore);
    }

    private static async Task<WebApplication> StartAppAsync(TestClock clock)
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        builder.Logging.ClearProviders();
        builder.Services.AddSingleton<TimeProvider>(clock);
        builder.Services.AddSingleton<IThreatProfileStore, InMemoryThreatProfileStore>();
        builder.Services.AddSingleton<InMemoryInteractionEventStore>();
        builder.Services.AddSingleton<ICredentialEvidenceStore, InMemoryCredentialEvidenceStore>();
        builder.Services.AddSingleton<ICredentialEvidenceAccessService, CredentialEvidenceAccessService>();
        var app = builder.Build();
        // 仅由测试宿主提供身份，端点仍使用生产的角色判断与响应合同。
        app.Use(async (context, next) =>
        {
            if (context.Request.Headers.TryGetValue("X-Test-Role", out var role))
                context.Items["CurrentUser"] = new AuthenticatedUser("isolated-admin", "isolated-admin", [role.ToString()]);
            await next();
        });
        app.MapPasswordBookEndpoints();
        app.MapCredentialEvidenceEndpoints();
        await app.StartAsync();
        return app;
    }

    private static HttpClient CreateAdminClient(WebApplication app)
    {
        var client = new HttpClient { BaseAddress = new Uri(Assert.Single(app.Urls)) };
        client.DefaultRequestHeaders.Add("X-Test-Role", "Administrator");
        return client;
    }

    private static async Task<JsonElement> ReadPageAsync(HttpClient client, int page = 1, int pageSize = 20, string? keyword = null)
    {
        var filter = keyword is null ? "" : $"&keyword={Uri.EscapeDataString(keyword)}";
        using var response = await client.GetAsync($"{Route}?page={page}&pageSize={pageSize}{filter}");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(response.Headers.CacheControl?.NoStore);
        var body = await response.Content.ReadAsStringAsync();
        Assert.DoesNotContain(Password, body);
        using var result = JsonDocument.Parse(body);
        Assert.True(result.RootElement.GetProperty("success").GetBoolean());
        var data = result.RootElement.GetProperty("data");
        // 固定字段合同，避免原文、密码指纹或加密证据内容意外进入列表。
        foreach (var row in data.GetProperty("items").EnumerateArray())
            Assert.Equal(new[] { "adapterKey", "authenticationCount", "credentialArtifactId", "lastUsedAtUtc", "username" },
                row.EnumerateObject().Select(field => field.Name).Order(StringComparer.Ordinal));
        return data.Clone();
    }

    private static async Task<InteractionEvent> SaveAsync(WebApplication app, string eventId, object content,
        string adapter = "ssh", string materialType = "Plaintext", string method = "password", string username = Account, int retentionDays = 1)
    {
        const string sourceIp = "192.0.2.10";
        var connectionId = $"connection-{eventId}";
        var evidence = await app.Services.GetRequiredService<ICredentialEvidenceStore>().SaveAsync(connectionId,
            eventId, sourceIp, adapter, materialType, JsonSerializer.Serialize(content), retentionDays);
        return new InteractionEvent
        {
            EventId = eventId, ConnectionId = connectionId, EventType = "AuthenticationAttempted", Outcome = "failure",
            OccurredAtUtc = evidence.CapturedAtUtc.AddSeconds(-1), SourceIp = sourceIp, DestinationIp = "127.0.0.1",
            ListenerId = "test-listener", ServiceInstanceId = "test-instance", AdapterKey = adapter, ProfileId = "test-profile",
            Username = username, AuthenticationMethod = method, CredentialCaptureStatus = "Captured",
            MaterialType = materialType, CredentialArtifactId = evidence.CredentialArtifactId,
        };
    }

    private static async Task AcceptAsync(WebApplication app, InteractionEvent item)
    {
        var result = await app.Services.GetRequiredService<InMemoryInteractionEventStore>().AppendAsync(item);
        Assert.True(result.Recorded);
        Assert.False(result.IsDuplicate);
    }

    private sealed class TestClock : TimeProvider
    {
        private DateTimeOffset _utc = new(2026, 11, 15, 0, 0, 0, TimeSpan.Zero);
        public override DateTimeOffset GetUtcNow() => _utc;
        public void Advance(TimeSpan duration) => _utc += duration;
    }
}
