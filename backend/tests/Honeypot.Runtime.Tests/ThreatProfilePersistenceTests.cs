using Honeypot.Api.Data;
using Honeypot.Api.Options;
using Honeypot.Api.Service.impl;
using Honeypot.Engine.Models;
using Honeypot.Protocol.Abstractions.Models;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using OptionsFactory = Microsoft.Extensions.Options.Options;
using Xunit;

namespace Honeypot.Runtime.Tests;

public sealed class ThreatProfilePersistenceTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 15, 8, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task CommittedProfileSurvivesNewStoreAndUncommittedUpdateRollsBack()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();
        var factory = await CreateFactoryAsync(connection);
        var clock = new TestClock();
        var store = CreateStore(factory, clock);
        var accepted = Event("first", "192.0.2.10", Now, "ConnectionAccepted", "ssh", 2222, 1);
        var first = await ApplyAsync(factory, store, accepted);

        // 重建存储服务与上下文，确认档案计算使用已提交数据。
        store = CreateStore(factory, clock);
        var authentication = Event("second", "::ffff:192.0.2.10", Now.AddTicks(-1),
            "AuthenticationAttempted", "mysql", 3306, 12);
        var updated = await ApplyAsync(factory, store, authentication);
        Assert.Equal(first.Profile.ThreatId, updated.Profile.ThreatId);
        Assert.Equal("Observed", updated.PreviousStatus);
        Assert.Equal("Suspicious", updated.Profile.Status);
        Assert.Equal(21, updated.Profile.CurrentScore);

        await ApplyAsync(factory, store, authentication with { EventId = "rolled-back" }, commit: false);
        var restored = Assert.IsType<ThreatIpProfile>(CreateStore(factory, clock).GetByIp("192.0.2.10"));
        Assert.Equal(updated.Profile.ThreatId, restored.ThreatId);
        Assert.Equal(2, restored.AttemptCount);
        Assert.Equal(1, restored.AuthenticationAttemptCount);
        Assert.Equal(Now.AddTicks(-1), restored.FirstSeenUtc);
        Assert.Equal(Now, restored.LastSeenUtc);
        Assert.Equal("second", restored.LastEventId);
        Assert.Equal(new[] { "mysql", "ssh" }, restored.ServicesTouched.Order());
        Assert.Equal(new[] { 2222, 3306 }, restored.PortsTouched.Order());
    }

    [Fact]
    public async Task QueriesIgnoreExpiredProfilesAndRespectFilterAndPage()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();
        var factory = await CreateFactoryAsync(connection);
        var clock = new TestClock();
        var store = CreateStore(factory, clock);
        var old = Event("old", "192.0.2.10", Now, "ConnectionAccepted", "ssh", 2222, 100);
        var expired = await ApplyAsync(factory, store, old);
        clock.UtcNow = Now.AddHours(1);
        await ApplyAsync(factory, store, old with { EventId = "active-1", SourceIp = "192.0.2.11", RiskDelta = 40 });
        await ApplyAsync(factory, store, old with { EventId = "active-2", SourceIp = "192.0.2.12", RiskDelta = 30 });
        clock.UtcNow = Now.AddDays(1);

        Assert.Null(store.GetByIp(old.SourceIp));
        Assert.Equal(2, store.Count());
        Assert.Equal("::ffff:192.0.2.11", Assert.Single(store.GetObservedSources([old.SourceIp, "::ffff:192.0.2.11"])));
        var page = store.Query(new(2, 1, ThreatProfileSort.RiskThenAuthenticationAttempts, MinimumScore: 20,
            Status: "suspicious", FromUtc: Now, ToUtc: Now.AddTicks(1)));
        Assert.Equal(2, page.Total);
        Assert.Equal("192.0.2.12", Assert.Single(page.Items).SourceIp);

        var newObservation = await ApplyAsync(factory, store, old with { EventId = "new", OccurredAtUtc = clock.UtcNow });
        Assert.NotEqual(expired.Profile.ThreatId, newObservation.Profile.ThreatId);
        Assert.Null(newObservation.PreviousStatus);
        Assert.Equal(1, Assert.IsType<ThreatIpProfile>(store.GetByIp(old.SourceIp)).AttemptCount);
    }

    private static async Task<TestFactory> CreateFactoryAsync(SqliteConnection connection)
    {
        var factory = new TestFactory(new DbContextOptionsBuilder<HoneypotDbContext>().UseSqlite(connection).Options);
        await using var db = factory.CreateDbContext();
        await db.Database.EnsureCreatedAsync();
        return factory;
    }

    private static SqliteThreatProfileStore CreateStore(TestFactory factory, TestClock clock) =>
        new(factory, OptionsFactory.Create(new EventStorageOptions { ThreatRetentionDays = 1 }), clock, new ResourceIdGenerator());

    private static async Task<(ThreatIpProfile Profile, string? PreviousStatus)> ApplyAsync(TestFactory factory,
        SqliteThreatProfileStore store, InteractionEvent interactionEvent, bool commit = true)
    {
        await using var db = factory.CreateDbContext();
        await using var transaction = await db.Database.BeginTransactionAsync();
        var change = await store.ApplyAsync(db, interactionEvent, CancellationToken.None);
        await db.SaveChangesAsync();
        if (commit) await transaction.CommitAsync();
        return change;
    }

    private static InteractionEvent Event(string id, string source, DateTimeOffset occurredAt, string kind, string adapter, int port, int risk) => new()
    {
        EventId = id, ConnectionId = "sample-connection", EventType = kind, OccurredAtUtc = occurredAt, SourceIp = source,
        DestinationIp = "192.0.2.20", DestinationPort = port, ListenerId = "sample-listener", ServiceInstanceId = "sample-instance",
        AdapterKey = adapter, ProfileId = "sample-profile", RiskDelta = risk,
    };

    private sealed class TestFactory(DbContextOptions<HoneypotDbContext> options) : IDbContextFactory<HoneypotDbContext>
    {
        public HoneypotDbContext CreateDbContext() => new(options);
    }

    private sealed class TestClock : TimeProvider
    {
        public DateTimeOffset UtcNow { get; set; } = Now;

        public override DateTimeOffset GetUtcNow() => UtcNow;
    }
}
