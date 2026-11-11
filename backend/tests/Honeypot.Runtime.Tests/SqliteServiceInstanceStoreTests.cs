using Honeypot.Api.Data;
using Honeypot.Api.Service.impl;
using Honeypot.Protocol.Abstractions.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Honeypot.Runtime.Tests;

/// <summary>
/// 验证实例配置、端口集合和重启策略在 SQLite 中可恢复。
/// </summary>
public sealed class SqliteServiceInstanceStoreTests
{
    [Fact]
    public async Task InstanceAndBindingsRoundTripPreservesRuntimeAndRestartPolicy()
    {
        var databasePath = Path.Combine(Path.GetTempPath(), $"honeypot-store-{Guid.NewGuid():N}.db");
        var connectionString = $"Data Source={databasePath}";
        await using var provider = BuildProvider(connectionString);
        var factory = provider.GetRequiredService<IDbContextFactory<HoneypotDbContext>>();
        await using (var db = await factory.CreateDbContextAsync())
        {
            await db.Database.MigrateAsync();
        }

        var store = new SqliteServiceInstanceStore(factory);
        var original = CreateInstance() with
        {
            DesiredState = "Running",
            AutoStart = true,
            CurrentState = "Running",
        };

        store.Upsert(original);
        var persisted = store.Get("ssh-default");
        Assert.NotNull(persisted);
        Assert.Equal("Running", persisted!.DesiredState);
        Assert.True(persisted.AutoStart);
        Assert.Equal("Running", persisted.CurrentState);
        Assert.Equal(new[] { 22222, 22223 }, persisted.Bindings.Select(item => item.Port));

        // 端口编辑请求通常只携带基础配置，不能覆盖已经持久化的运行态。
        store.Upsert(original with
        {
            DisplayName = "SSH 蜜罐（已修改）",
            Bindings = new[]
            {
                original.Bindings[0],
                new ListenerBinding
                {
                    ListenerId = "ssh-default-22224",
                    Port = 22224,
                },
            },
        });

        var reopened = store.Get("ssh-default");
        Assert.NotNull(reopened);
        Assert.Equal("SSH 蜜罐（已修改）", reopened!.DisplayName);
        Assert.Equal("Running", reopened.DesiredState);
        Assert.True(reopened.AutoStart);
        Assert.Equal("Running", reopened.CurrentState);
        Assert.Equal(new[] { 22222, 22224 }, reopened.Bindings.Select(item => item.Port));

        store.SetRuntimeState("ssh-default", "Failed", "端口被占用");
        store.SetDesiredState("ssh-default", "Stopped", autoStart: false);
        var updated = store.Get("ssh-default");
        Assert.NotNull(updated);
        Assert.Equal("Stopped", updated!.DesiredState);
        Assert.False(updated.AutoStart);
        Assert.Equal("Failed", updated.CurrentState);
        Assert.Equal("端口被占用", updated.LastError);
    }

    [Fact]
    public async Task MigrationCreatesTablesOnFreshDatabase()
    {
        var databasePath = Path.Combine(Path.GetTempPath(), $"honeypot-migration-{Guid.NewGuid():N}.db");
        await using var provider = BuildProvider($"Data Source={databasePath}");
        var factory = provider.GetRequiredService<IDbContextFactory<HoneypotDbContext>>();
        await using var db = await factory.CreateDbContextAsync();

        await db.Database.MigrateAsync();

        var tables = await db.Database.SqlQueryRaw<string>(
            "SELECT name AS Value FROM sqlite_master WHERE type = 'table' ORDER BY name").ToListAsync();
        Assert.Contains("service_instances", tables);
        Assert.Contains("listener_bindings", tables);
        Assert.Contains("__EFMigrationsHistory", tables);
    }

    private static ServiceProvider BuildProvider(string connectionString)
    {
        var services = new ServiceCollection();
        services.AddDbContextFactory<HoneypotDbContext>(options => options.UseSqlite(connectionString));
        return services.BuildServiceProvider();
    }

    private static ServiceInstance CreateInstance() => new()
    {
        InstanceId = "ssh-default",
        DisplayName = "SSH 蜜罐",
        AdapterKey = "ssh",
        Profile = new ServiceProfile
        {
            ProfileId = "ssh-default-profile",
            AdapterKey = "ssh",
            AdvertisedProduct = "OpenSSH",
            AdvertisedVersion = "9.6p1 Ubuntu-3ubuntu13.5",
        },
        Bindings = new[]
        {
            new ListenerBinding
            {
                ListenerId = "ssh-default-22222",
                Port = 22222,
            },
            new ListenerBinding
            {
                ListenerId = "ssh-default-22223",
                Port = 22223,
            },
        },
    };
}
