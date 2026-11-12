using Honeypot.Api.Data;
using Honeypot.Api.Data.Models;
using Honeypot.Api.Models;
using Honeypot.Api.Service;
using Honeypot.Api.Service.impl;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Xunit;

namespace Honeypot.Runtime.Tests;

public sealed class McpPersistenceTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 11, 8, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task MigrationAddsOnlyMcpTablesAndPreservesLegacyData()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();
        var dbFactory = Factory(connection);
        await using var db = dbFactory.CreateDbContext();
        await db.GetService<IMigrator>().MigrateAsync("20261110135715_ReportNotifications");
        db.ServiceInstances.Add(new ServiceInstanceEntity
        {
            InstanceId = "isolated-instance", DisplayName = "隔离样本", AdapterKey = "ssh",
            ProfileJson = "{}", DesiredState = "Stopped", CurrentState = "Stopped", CreatedAtUtc = Now, UpdatedAtUtc = Now,
        });
        db.Set<ReportSourceFirstSeenEntity>().Add(new() { SourceIp = "192.0.2.21", FirstSeenAtUnixMs = Now.ToUnixTimeMilliseconds() });
        await db.SaveChangesAsync();
        var before = await TableNames(db);
        await db.Database.MigrateAsync();
        await db.Database.MigrateAsync();
        var after = await TableNames(db);
        Assert.Equal(new[] { "mcp_api_keys", "mcp_call_audits", "mcp_settings" }, after.Except(before).Order().ToArray());
        Assert.All(before, table => Assert.Contains(table, after));
        Assert.False(db.Database.HasPendingModelChanges());
        Assert.Equal("隔离样本", (await db.ServiceInstances.AsNoTracking().SingleAsync()).DisplayName);
        Assert.Equal("192.0.2.21", (await db.Set<ReportSourceFirstSeenEntity>().AsNoTracking().SingleAsync()).SourceIp);
        var store = CreateStore(dbFactory, new TestClock(Now));
        var settings = await store.GetSettingsAsync();
        Assert.False(settings.Enabled);
        Assert.Equal(30, settings.AuditRetentionDays);
    }

    [Fact]
    public async Task KeyExpiryRevocationAndDeletionPreserveHistoryAndOnlyStoreDigest()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();
        var factory = Factory(connection);
        await using var db = factory.CreateDbContext();
        await db.Database.MigrateAsync();
        var clock = new TestClock(Now);
        var store = CreateStore(factory, clock);
        await store.UpdateSettingsAsync(new(true, null), "operator", default);
        await store.UpdateSettingsAsync(new(null, 25), "operator", default);
        var created = await store.CreateKeyAsync("审计验证", McpAccess.ReadOnly, ["get_overview"], [], Now.AddMinutes(5), "operator", default);
        Assert.StartsWith(created.Key.Prefix + ".", created.Secret, StringComparison.Ordinal);
        var wrongSecret = created.Secret[..^1] + (created.Secret[^1] == 'A' ? "B" : "A");
        Assert.Null((await store.AuthenticateAsync(wrongSecret)).Key);
        var stored = await db.Set<McpApiKeyEntity>().AsNoTracking().SingleAsync();
        Assert.Equal(32, stored.SecretDigest.Length);
        Assert.DoesNotContain(created.Secret, System.Text.Json.JsonSerializer.Serialize(stored));

        // 新服务实例从同一 SQLite 读回服务状态和凭据授权。
        store = CreateStore(factory, clock);
        Assert.True((await store.GetSettingsAsync()).Enabled);
        Assert.Equal(25, (await store.GetSettingsAsync()).AuditRetentionDays);
        Assert.Equal("OK", (await store.AuthenticateAsync(created.Secret)).Code);
        await store.TouchKeyAsync(created.Key.Id);
        Assert.Equal(Now, (await store.GetKeysAsync(1, 20, default)).Items.Single().LastUsedAtUtc);
        Assert.Equal("MCP_KEY_REVOKE_REQUIRED", await store.DeleteKeyAsync(created.Key.Id, default));

        var entry = Sample(Now) with { KeyId = created.Key.Id, KeyName = created.Key.Name, KeyPrefix = created.Key.Prefix };
        var auditId = await store.BeginAuditAsync(entry);
        await store.CompleteAuditAsync(auditId, entry with { Result = McpAuditResult.Success, ResponseBody = "{\"count\":1}" });
        clock.Now = Now.AddMinutes(5);
        Assert.Equal("API_KEY_EXPIRED", (await store.AuthenticateAsync(created.Secret)).Code);
        Assert.True(await store.RevokeKeyAsync(created.Key.Id, default));
        Assert.Equal("API_KEY_REVOKED", (await store.AuthenticateAsync(created.Secret)).Code);
        Assert.Equal("OK", await store.DeleteKeyAsync(created.Key.Id, default));
        Assert.Null((await store.AuthenticateAsync(created.Secret)).Key);

        var history = await store.GetAuditsAsync(new(1, 20, created.Key.Id, "get_overview", "192.0.2.22",
            McpAuditResult.Success, Now, Now.AddHours(1)), default);
        Assert.Equal("tools/call", Assert.Single(history.Items).McpMethod);
        var details = await store.GetAuditAsync(auditId, default);
        Assert.Equal(created.Key.Name, details!.KeyName);
        Assert.Equal("{\"count\":1}", details.ResponseBody);
    }

    [Fact]
    public async Task ShorterRetentionHidesAndRemovesOldAuditsAndClassifiesUnfinishedCalls()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();
        var factory = Factory(connection);
        await using var db = factory.CreateDbContext();
        await db.Database.MigrateAsync();
        var clock = new TestClock(Now);
        var store = CreateStore(factory, clock);
        var old = await store.BeginAuditAsync(Sample(Now.AddDays(-2)));
        var pending = await store.BeginAuditAsync(Sample(Now.AddMinutes(-3)));
        await store.RecordAuditAsync(Sample(Now) with { Result = McpAuditResult.Denied });
        Assert.NotNull(await store.GetAuditAsync(old, default));
        Assert.Equal(McpAuditResult.Unknown, (await store.GetAuditAsync(pending, default))!.Result);
        await store.UpdateSettingsAsync(new(null, 1), "operator", default);
        Assert.Null(await store.GetAuditAsync(old, default));
        Assert.Equal(pending, Assert.Single((await store.GetAuditsAsync(
            new(1, 20, null, null, null, McpAuditResult.Unknown, null, null), default)).Items).Id);
        Assert.Equal(1, await store.DeleteExpiredAuditsAsync(1, default));
        Assert.False(await db.Set<McpCallAuditEntity>().AnyAsync(row => row.Id == old));
        Assert.Equal(2, await db.Set<McpCallAuditEntity>().CountAsync());
    }

    private static McpAuditEntry Sample(DateTimeOffset time) => new()
    {
        OccurredAtUtc = time, HttpMethod = "POST", Path = "/mcp", McpMethod = "tools/call", ToolName = "get_overview",
        SourceIp = "192.0.2.22", Result = McpAuditResult.Pending,
    };

    private static Task<List<string>> TableNames(HoneypotDbContext db) =>
        db.Database.SqlQueryRaw<string>("SELECT name AS Value FROM sqlite_master WHERE type = 'table'").ToListAsync();

    private static SqliteMcpStore CreateStore(IDbContextFactory<HoneypotDbContext> factory, TimeProvider clock) =>
        new(factory, new ResourceIdGenerator(), clock, new McpAuditHealth());

    private static TestDbFactory Factory(SqliteConnection connection) =>
        new(new DbContextOptionsBuilder<HoneypotDbContext>().UseSqlite(connection).Options);

    private sealed class TestDbFactory(DbContextOptions<HoneypotDbContext> options) : IDbContextFactory<HoneypotDbContext>
    {
        public HoneypotDbContext CreateDbContext() => new(options);
    }

    private sealed class TestClock(DateTimeOffset now) : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = now;
        public override DateTimeOffset GetUtcNow() => Now;
    }
}
