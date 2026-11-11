using Honeypot.Api.Data;
using Honeypot.Api.Data.Models;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Xunit;

namespace Honeypot.Runtime.Tests;

/// <summary>只在内存 SQLite 中执行迁移，验证新增六表不会改写存量实例与监听配置。</summary>
public sealed class NotificationMigrationTests
{
    [Fact]
    public async Task UpgradeAddsSixReportTablesAndPreservesExistingConfiguration()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();
        var options = new DbContextOptionsBuilder<HoneypotDbContext>().UseSqlite(connection).Options;
        await using var db = new HoneypotDbContext(options);
        await db.GetService<IMigrator>().MigrateAsync("20261108161732_InitialCreate");
        db.ServiceInstances.Add(new ServiceInstanceEntity
        {
            InstanceId = "isolated-service", DisplayName = "隔离迁移样本", AdapterKey = "ssh", ProfileJson = "{}",
            DesiredState = "Stopped", CurrentState = "Stopped", AutoStart = false,
            CreatedAtUtc = DateTimeOffset.UnixEpoch, UpdatedAtUtc = DateTimeOffset.UnixEpoch,
            Bindings = [new ListenerBindingEntity
            {
                ListenerId = "isolated-listener", InstanceId = "isolated-service", BindAddress = "127.0.0.1",
                Port = 22222, Transport = "tcp", Enabled = false, MaxConnections = 4, MaxConnectionsPerIp = 1,
            }],
        });
        await db.SaveChangesAsync();
        await db.Database.MigrateAsync();
        await db.Database.MigrateAsync(); // 重复启动迁移必须幂等。
        db.ChangeTracker.Clear();
        var original = await db.ServiceInstances.Include(row => row.Bindings).SingleAsync();
        Assert.Equal("隔离迁移样本", original.DisplayName);
        Assert.False(original.AutoStart);
        Assert.Equal(22222, Assert.Single(original.Bindings).Port);
        var tables = await db.Database.SqlQueryRaw<string>("SELECT name AS Value FROM sqlite_master WHERE type='table'").ToListAsync();
        foreach (var table in new[] { "report_events", "report_source_first_seen", "report_runtime_samples", "report_snapshots", "email_deliveries", "email_delivery_attempts" })
            Assert.Contains(table, tables);
        Assert.False(db.Database.HasPendingModelChanges());
    }

    [Fact]
    public async Task AutomaticReportBusinessKeyCannotBeCreatedTwice()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();
        var options = new DbContextOptionsBuilder<HoneypotDbContext>().UseSqlite(connection).Options;
        await using var db = new HoneypotDbContext(options);
        await db.Database.MigrateAsync();
        db.Add(new ReportSnapshotEntity { Id = "first", PeriodKind = "Daily", TaskKey = "automatic:Daily:1:2", ReportJson = "{}" });
        await db.SaveChangesAsync();
        db.Add(new ReportSnapshotEntity { Id = "second", PeriodKind = "Daily", TaskKey = "automatic:Daily:1:2", ReportJson = "{}" });
        await Assert.ThrowsAsync<DbUpdateException>(() => db.SaveChangesAsync());
        db.ChangeTracker.Clear();
        Assert.Equal(1, await db.Set<ReportSnapshotEntity>().CountAsync());
    }
}
