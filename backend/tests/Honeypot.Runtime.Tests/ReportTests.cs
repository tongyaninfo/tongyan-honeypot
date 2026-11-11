using Honeypot.Api.Data;
using Honeypot.Api.Data.Models;
using Honeypot.Api.Service.impl;
using Honeypot.Engine.Service.impl;
using Honeypot.Protocol.Abstractions.Models;
using Honeypot.Shared.Models;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Honeypot.Runtime.Tests;

/// <summary>隔离 SQLite 内存库验证真实 SQL 聚合、幂等、半开边界与采集未知，不接触工作目录数据库。</summary>
public sealed class ReportTests
{
    private static readonly DateTimeOffset Start = new(2026, 11, 9, 16, 0, 0, TimeSpan.Zero);

    [Fact]
    public void CalendarPeriodsUseShanghaiMondayAndPreviousComparableElapsedPeriod()
    {
        var now = new DateTimeOffset(2026, 11, 10, 4, 0, 0, TimeSpan.Zero);
        var (day, previousDay, previousEnd) = SqliteReportService.ResolvePeriod(new() { Period = "day" }, now);
        Assert.Equal(Start, day.StartAtUtc);
        Assert.Equal(Start.AddDays(-1), previousDay);
        Assert.Equal(now.AddDays(-1), previousEnd);
        var (week, _, _) = SqliteReportService.ResolvePeriod(new() { Period = "week" }, now);
        Assert.Equal(new DateTimeOffset(2026, 11, 8, 16, 0, 0, TimeSpan.Zero), week.StartAtUtc);
        var (month, oldMonth, _) = SqliteReportService.ResolvePeriod(new() { Period = "month" }, now);
        Assert.Equal(new DateTimeOffset(2026, 10, 31, 16, 0, 0, TimeSpan.Zero), month.StartAtUtc);
        Assert.Equal(new DateTimeOffset(2026, 9, 30, 16, 0, 0, TimeSpan.Zero), oldMonth);
        var (_, previousMonthStart, previousMonthEnd) = SqliteReportService.ResolvePeriod(new()
        {
            Period = "custom", StartAtUtc = new DateTimeOffset(2026, 9, 30, 16, 0, 0, TimeSpan.Zero),
            EndAtUtc = new DateTimeOffset(2026, 10, 31, 16, 0, 0, TimeSpan.Zero),
        }, now);
        Assert.Equal(new DateTimeOffset(2026, 8, 31, 16, 0, 0, TimeSpan.Zero), previousMonthStart);
        Assert.Equal(new DateTimeOffset(2026, 9, 30, 16, 0, 0, TimeSpan.Zero), previousMonthEnd);
        Assert.Throws<ArgumentException>(() => SqliteReportService.ResolvePeriod(new() { Period = "custom", StartAtUtc = now.AddDays(-367), EndAtUtc = now }, now));
        Assert.Throws<ArgumentException>(() => SqliteReportService.ResolvePeriod(new() { Period = "custom", StartAtUtc = now.AddDays(-1), EndAtUtc = now.AddSeconds(1) }, now));
    }

    [Fact]
    public async Task SqliteCountsUniqueSourcesFailureVariantsEvidenceAndExcludesEndBoundary()
    {
        await using var fixture = await Fixture.CreateAsync();
        var store = fixture.Store();
        var first = Event("accepted", "ConnectionAccepted", Start);
        Assert.True((await store.AppendAsync(first)).Recorded);
        await store.AppendAsync(first);
        await store.AppendAsync(Event("handshake", "HandshakeReceived", Start.AddMinutes(1)));
        foreach (var outcome in new[] { "failure", "rejected", "invalid" })
            await store.AppendAsync(Event(outcome, "AuthenticationAttempted", Start.AddMinutes(2)) with
            {
                Outcome = outcome, Username = "test-user", AuthenticationMethod = "password", CredentialArtifactId = "artifact-1",
                MaterialType = "Plaintext", Password = "never-persist-this", PayloadSummary = "do-not-store-payload", RiskDelta = 5,
            });
        await store.AppendAsync(Event("second-source", "ProtocolViolation", Start.AddMinutes(3)) with { SourceIp = "192.0.2.11", CaptureTruncated = true });
        await store.AppendAsync(Event("closed", "SessionClosed", Start.AddMinutes(4)));
        await store.AppendAsync(Event("end-excluded", "ConnectionAccepted", Start.AddHours(1)));
        await fixture.SampleAsync(Start, Start.AddHours(1));

        var report = await fixture.ReportAsync(Start, Start.AddHours(1));
        Assert.Equal(7, report.Totals.EventCount);
        Assert.Equal(1, report.Totals.AcceptedConnections);
        Assert.Equal(2, report.Totals.UniqueSourceIps);
        Assert.Equal(2, report.Totals.NewSourceIps);
        Assert.Equal(3, report.Totals.AuthenticationFailures);
        Assert.Equal(1, report.Totals.EvidenceCount);
        Assert.Equal(1, report.Totals.TruncatedEvents);
        Assert.Equal(1, report.Totals.SessionClosed);
        Assert.Equal("complete", report.Coverage.Status);
        Assert.Equal(3, Assert.Single(report.AuthenticationMethods).AuthenticationFailures);
        Assert.Single(report.Usernames);
        Assert.Single(report.Evidence);
        Assert.Equal(7, report.Trend.Sum(item => item.Events));
        await using var db = fixture.Factory.CreateDbContext();
        var fact = await db.Set<ReportEventEntity>().SingleAsync(item => item.EventId == "failure");
        var json = System.Text.Json.JsonSerializer.Serialize(fact);
        Assert.DoesNotContain("never-persist-this", json);
        Assert.DoesNotContain("do-not-store-payload", json);
        Assert.DoesNotContain("Password", json);
        Assert.Equal(8, await db.Set<ReportEventEntity>().CountAsync());
        // 重建内存服务不会影响已持久化的报告，报告也不依赖原事件 GetAll。
        Assert.Empty(fixture.Store().GetAll());
        Assert.Equal(report.Totals, (await fixture.ReportAsync(Start, Start.AddHours(1))).Totals);
    }

    [Fact]
    public async Task MissingCollectionIsUnknownWhileCoveredQuietPeriodIsZero()
    {
        await using var fixture = await Fixture.CreateAsync();
        var missing = await fixture.ReportAsync(Start, Start.AddHours(1));
        Assert.Equal("unknown", missing.Coverage.Status);
        Assert.Null(missing.Totals.EventCount);
        Assert.Null(missing.Runtime.AverageProcessCpuPercent);
        Assert.Null(Assert.Single(missing.Trend).Events);
        Assert.Equal("unknown", Assert.Single(missing.Trend).CoverageStatus);
        await fixture.SampleAsync(Start, Start.AddHours(1));
        var quiet = await fixture.ReportAsync(Start, Start.AddHours(1));
        Assert.Equal("complete", quiet.Coverage.Status);
        Assert.Equal(0, quiet.Totals.EventCount);
        Assert.Equal(3600, quiet.Coverage.CoveredSeconds);
        Assert.Equal(0, Assert.Single(quiet.Trend).Events);
        Assert.Equal("complete", Assert.Single(quiet.Trend).CoverageStatus);
        Assert.Null(quiet.Comparison.ConnectionChangePercent);
    }

    [Fact]
    public async Task SamplingGapAndPersistenceFailureCannotBecomeHealthyCoverage()
    {
        await using var fixture = await Fixture.CreateAsync();
        await fixture.SampleAsync(Start, Start.AddMinutes(10));
        await fixture.SampleAsync(Start.AddMinutes(20), Start.AddMinutes(30), failures: 1);
        await fixture.SampleAsync(Start.AddMinutes(40), Start.AddMinutes(50));
        var report = await fixture.ReportAsync(Start, Start.AddHours(1));
        Assert.Equal("partial", report.Coverage.Status);
        Assert.Equal(1200, report.Coverage.CoveredSeconds);
        Assert.Equal(2400, report.Coverage.UnknownSeconds);
        Assert.Equal(1, report.Coverage.PersistenceFailures);
        Assert.Null(report.Comparison.ConnectionChangePercent);
    }

    [Fact]
    public async Task ShortPreviousMonthCannotProduceSameElapsedChangeEvenWithCompleteCoverage()
    {
        await using var fixture = await Fixture.CreateAsync();
        var now = new DateTimeOffset(2026, 10, 31, 12, 0, 0, TimeSpan.FromHours(8));
        var (period, previousStart, previousEnd) = SqliteReportService.ResolvePeriod(new() { Period = "month" }, now);
        Assert.Equal(TimeSpan.FromDays(30.5), period.EndAtUtc - period.StartAtUtc);
        Assert.Equal(TimeSpan.FromDays(30), previousEnd - previousStart);
        await fixture.SampleAsync(previousStart, previousEnd);
        await fixture.SampleAsync(period.StartAtUtc, period.EndAtUtc);
        var store = fixture.Store();
        await store.AppendAsync(Event("prior-month", "ConnectionAccepted", previousStart));
        await store.AppendAsync(Event("this-month", "ConnectionAccepted", period.StartAtUtc));
        var report = await new SqliteReportService(fixture.Factory, new FixedTime(now)).GenerateAsync(new() { Period = "month" });
        Assert.Equal("complete", report.Coverage.Status);
        Assert.Equal("complete", report.Comparison.CoverageStatus);
        Assert.Null(report.Comparison.ConnectionChangePercent);
        Assert.Null(report.Comparison.SourceIpChangePercent);
        Assert.Contains(report.Notes, note => note.Contains("时长不同", StringComparison.Ordinal));
        Assert.All(report.Trend, point => Assert.Equal("complete", point.CoverageStatus));
    }

    [Fact]
    public async Task OverlappingSamplingIntervalsUseUnionInsteadOfHidingMissingTime()
    {
        await using var fixture = await Fixture.CreateAsync();
        // 原始SUM已超过一小时，但这三个重复/嵌套区间实际只覆盖前45分钟。
        await fixture.SampleAsync(Start, Start.AddMinutes(40));
        await fixture.SampleAsync(Start.AddMinutes(5), Start.AddMinutes(35));
        await fixture.SampleAsync(Start.AddMinutes(20), Start.AddMinutes(45));
        var report = await fixture.ReportAsync(Start, Start.AddHours(1));
        Assert.Equal(2700, report.Coverage.CoveredSeconds);
        Assert.Equal(900, report.Coverage.UnknownSeconds);
        Assert.Equal(75, report.Coverage.CoveragePercent);
        Assert.Equal("partial", report.Coverage.Status);
        Assert.Equal("partial", Assert.Single(report.Trend).CoverageStatus);
    }

    [Fact]
    public async Task LateEarlierEventCorrectsFirstSeenAcrossPeriods()
    {
        await using var fixture = await Fixture.CreateAsync();
        var store = fixture.Store();
        await store.AppendAsync(Event("later", "ConnectionAccepted", Start.AddMinutes(1)));
        await store.AppendAsync(Event("earlier", "ConnectionAccepted", Start.AddDays(-1)));
        var report = await fixture.ReportAsync(Start, Start.AddHours(1));
        Assert.Equal(1, report.Totals.UniqueSourceIps);
        Assert.Equal(0, report.Totals.NewSourceIps);
        Assert.Null(report.Comparison.Totals.NewSourceIps); // 上期仅相邻 1 小时，无观测。
    }

    [Fact]
    public async Task DatabaseFailureReturnsDegradedBeforeInMemoryAcceptAndIsObservable()
    {
        await using var fixture = await Fixture.CreateAsync(createSchema: false);
        var store = fixture.Store();
        var result = await store.AppendAsync(Event("not-recorded", "ConnectionAccepted", Start));
        Assert.False(result.Recorded);
        Assert.True(result.Degraded);
        Assert.Equal("REPORT_PERSISTENCE_FAILED", result.Code);
        Assert.Equal(1, fixture.Health.PersistenceFailures);
        Assert.Empty(store.GetAll());
    }

    private static InteractionEvent Event(string id, string type, DateTimeOffset at) => new()
    {
        EventId = id, ConnectionId = "connection", EventType = type, OccurredAtUtc = at, SourceIp = "192.0.2.10",
        DestinationIp = "192.0.2.100", DestinationPort = 2222, ListenerId = "listener", ServiceInstanceId = "instance",
        AdapterKey = "ssh", ProfileId = "profile",
    };

    private sealed class FixedTime(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    private sealed class Factory(DbContextOptions<HoneypotDbContext> options) : IDbContextFactory<HoneypotDbContext>
    {
        public HoneypotDbContext CreateDbContext() => new(options);
    }

    private sealed class Fixture(SqliteConnection connection, Factory factory) : IAsyncDisposable
    {
        private readonly InMemoryCredentialEvidenceStore _evidence = new();
        public Factory Factory { get; } = factory;
        public ReportIngestionHealth Health { get; } = new();
        public static async Task<Fixture> CreateAsync(bool createSchema = true)
        {
            var connection = new SqliteConnection("Data Source=:memory:");
            await connection.OpenAsync();
            var factory = new Factory(new DbContextOptionsBuilder<HoneypotDbContext>().UseSqlite(connection).Options);
            if (createSchema)
            {
                await using var db = factory.CreateDbContext();
                await db.Database.EnsureCreatedAsync();
            }
            return new(connection, factory);
        }
        public ReportInteractionEventStore Store() => new(Factory,
            new InMemoryInteractionEventStore(new InMemoryThreatProfileStore(), _evidence), Health,
            NullLogger<ReportInteractionEventStore>.Instance);
        public Task<OperationReport> ReportAsync(DateTimeOffset start, DateTimeOffset end) =>
            new SqliteReportService(Factory, new FixedTime(Start.AddDays(2))).GenerateAsync(new() { Period = "custom", StartAtUtc = start, EndAtUtc = end });
        public async Task SampleAsync(DateTimeOffset start, DateTimeOffset end, long failures = 0)
        {
            await using var db = Factory.CreateDbContext();
            db.Set<ReportRuntimeSampleEntity>().Add(new()
            {
                CapturedAtUnixMs = end.ToUnixTimeMilliseconds(), CoverageStartAtUnixMs = start.ToUnixTimeMilliseconds(),
                ConfiguredListeners = 2, RunningListeners = 2, ProcessCpuPercent = 10, ProcessMemoryBytes = 4096, PersistenceFailures = failures,
            });
            await db.SaveChangesAsync();
        }
        public async ValueTask DisposeAsync()
        {
            _evidence.Dispose();
            await connection.DisposeAsync();
        }
    }
}
