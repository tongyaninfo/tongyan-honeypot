using System.Globalization;
using Honeypot.Api.Data;
using Honeypot.Api.Data.Models;
using Honeypot.Api.Models;
using Honeypot.Api.Options;
using Honeypot.Api.Service.impl;
using Honeypot.Api.Workers;
using Honeypot.Engine.Service.impl;
using Honeypot.Protocol.Abstractions.Models;
using Honeypot.Shared.Models;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using OptionsFactory = Microsoft.Extensions.Options.Options;
using Xunit;

namespace Honeypot.Runtime.Tests;

/// <summary>隔离 SQLite 验证真实 SQL 聚合、幂等、半开边界和采集缺口。</summary>
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
        Assert.True((await store.AppendAsync(first)).IsDuplicate);
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
        // 重建写入服务后，详细事件和报告仍可读取，重投同一事件也不会增加计数。
        var restarted = await fixture.RecreateStoreAsync();
        Assert.Equal(8, restarted.GetAll().Count);
        Assert.True((await restarted.AppendAsync(first)).IsDuplicate);
        var detail = Assert.Single(restarted.GetByConnectionId("connection"), item => item.EventId == "failure");
        Assert.Null(detail.Password);
        Assert.Equal("artifact-1", detail.CredentialArtifactId);
        Assert.Equal(7, fixture.Threats().GetByIp("192.0.2.10")!.AttemptCount);
        Assert.Equal(report.Totals, (await fixture.ReportAsync(Start, Start.AddHours(1))).Totals);
    }

    [Fact]
    public async Task OverviewTrendReadsLegacyAndNewFactsAcrossDatabaseReopenAndDistinguishesMissingHours()
    {
        var currentHour = Start.AddHours(23);
        var now = currentHour.AddMinutes(17).ToOffset(TimeSpan.FromHours(8));
        var clock = new FixedTime(now.ToUniversalTime());
        var storage = new EventStorageOptions { MemoryEventCapacity = 2, MemoryRetentionHours = 1 };
        var path = Path.Combine(Directory.CreateTempSubdirectory("honeypot-overview-trend-").FullName, "overview.db");
        HourlyActivityMetric[] beforeRestart;

        await using (var fixture = await Fixture.CreateAsync(time: clock, storage: storage, databasePath: path))
        {
            await using (var db = fixture.Factory.CreateDbContext())
            {
                // 旧版本只保存报表事实，没有可与之匹配的事件详情。
                db.Set<ReportEventEntity>().AddRange(
                    new ReportEventEntity { EventId = "legacy-before-window", EventType = "connectionaccepted",
                        OccurredAtUnixMs = Start.AddMilliseconds(-1).ToUnixTimeMilliseconds() },
                    new ReportEventEntity { EventId = "legacy-at-start", EventType = "connectionaccepted",
                        OccurredAtUnixMs = Start.ToUnixTimeMilliseconds() },
                    new ReportEventEntity { EventId = "legacy-failure", EventType = "authenticationattempted",
                        IsAuthenticationFailure = true, OccurredAtUnixMs = Start.AddMinutes(1).ToUnixTimeMilliseconds() });
                await db.SaveChangesAsync();
            }

            var store = fixture.Store();
            var activityHour = Start.AddHours(2);
            foreach (var step in new[]
            {
                Event("observed-connection-1", "ConnectionAccepted", activityHour),
                Event("observed-connection-2", "ConnectionAccepted", activityHour.AddMinutes(1)),
                Event("observed-connection-3", "ConnectionAccepted", activityHour.AddMinutes(2)),
                Event("strict-failure", "AuthenticationAttempted", activityHour.AddMinutes(3)) with { Outcome = "FaILuRe" },
                Event("report-rejected", "AuthenticationAttempted", activityHour.AddMinutes(4)) with { Outcome = "rejected" },
                Event("report-invalid", "AuthenticationAttempted", activityHour.AddMinutes(5)) with { Outcome = " invalid " },
                Event("not-a-failure", "AuthenticationAttempted", activityHour.AddMinutes(6)) with { Outcome = "completed" },
                Event("not-a-connection", "HandshakeReceived", activityHour.AddMinutes(7)),
                Event("just-before-now", "ConnectionAccepted", now.AddMilliseconds(-1)),
                Event("at-now-excluded", "ConnectionAccepted", now),
                Event("after-now-excluded", "AuthenticationAttempted", now.AddMilliseconds(1)) with { Outcome = "failure" },
                Event("next-hour-excluded", "ConnectionAccepted", currentHour.AddHours(1)),
            })
                Assert.True((await store.AppendAsync(step)).Recorded);

            await fixture.SampleAsync(Start.AddHours(1), Start.AddHours(2));
            await fixture.SampleAsync(activityHour.AddMinutes(1), activityHour.AddMinutes(25));
            await fixture.SampleAsync(Start.AddHours(3), Start.AddHours(4), failures: 1);
            await fixture.SampleAsync(currentHour, now);

            Assert.Equal(2, store.GetAll().Count);
            var details = store.ReadEvents(new()).Items;
            Assert.Contains(details, item => item.EventId == "observed-connection-1");
            Assert.DoesNotContain(details, item => item.EventId == "legacy-at-start");
            var reports = new SqliteReportService(fixture.Factory, clock, storageOptions: OptionsFactory.Create(storage));
            beforeRestart = (await reports.ReadOverviewActivityAsync(now)).ToArray();
        }

        // 关闭写入器和数据库连接，再从同一个隔离文件读取，不依赖进程内事件视图。
        await using var reopened = await Fixture.CreateAsync(createSchema: false, time: clock, storage: storage, databasePath: path);
        var reopenedReports = new SqliteReportService(reopened.Factory, clock, storageOptions: OptionsFactory.Create(storage));
        var trend = (await reopenedReports.ReadOverviewActivityAsync(now)).ToArray();
        Assert.Equal(beforeRestart, trend);
        Assert.Equal(Enumerable.Range(0, 24).Select(hour =>
            Start.AddHours(hour).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture)), trend.Select(point => point.Key));
        Assert.Equal(((long?)1, (long?)1, "unknown"), (trend[0].AcceptedConnections, trend[0].AuthenticationFailures, trend[0].CoverageStatus));
        Assert.Equal(((long?)0, (long?)0, "complete"), (trend[1].AcceptedConnections, trend[1].AuthenticationFailures, trend[1].CoverageStatus));
        Assert.Equal(((long?)3, (long?)3, "partial"), (trend[2].AcceptedConnections, trend[2].AuthenticationFailures, trend[2].CoverageStatus));
        Assert.All(trend[3..23], point =>
        {
            Assert.Null(point.AcceptedConnections);
            Assert.Null(point.AuthenticationFailures);
            Assert.Equal("unknown", point.CoverageStatus);
        });
        Assert.Equal(((long?)1, (long?)0, "complete"), (trend[23].AcceptedConnections, trend[23].AuthenticationFailures, trend[23].CoverageStatus));

        var atHourBoundary = (await reopenedReports.ReadOverviewActivityAsync(currentHour)).ToArray();
        Assert.Equal(trend.Select(point => point.Key), atHourBoundary.Select(point => point.Key));
        Assert.Null(atHourBoundary[23].AcceptedConnections);
        Assert.Null(atHourBoundary[23].AuthenticationFailures);
        Assert.Equal("unknown", atHourBoundary[23].CoverageStatus);
    }

    [Fact]
    public async Task SqlQueriesPreserveConnectionActivityAndHideExpiredDetails()
    {
        var clock = new MutableTime(Start);
        await using var fixture = await Fixture.CreateAsync(time: clock, storage: new EventStorageOptions
        {
            MemoryEventCapacity = 2, MemoryRetentionHours = 1, DetailRetentionDays = 2,
        });
        var store = fixture.Store();
        var old = Event("old-accepted", "ConnectionAccepted", Start) with { ConnectionId = "old" };
        Assert.True((await store.AppendAsync(old)).Recorded);
        clock.Advance(TimeSpan.FromHours(2));
        var reached = clock.GetUtcNow();
        var accepted = Event("auth-accepted", "ConnectionAccepted", reached) with { ConnectionId = "auth", Sequence = 1 };
        var attempt = accepted with { EventId = "auth-first", EventType = "AuthenticationAttempted", Sequence = 2,
            OccurredAtUtc = reached.AddMinutes(1), AuthenticationAttempt = 1, Username = "sample-user" };
        var scan = accepted with { EventId = "scan-accepted", ConnectionId = "scan", SourceIp = "192.0.2.11" };
        foreach (var step in new[]
        {
            accepted,
            attempt with { EventId = "auth-second", Sequence = 3, AuthenticationAttempt = 2, OccurredAtUtc = reached.AddMinutes(2) },
            attempt,
            accepted with { EventId = "auth-closed", EventType = "SessionClosed", Sequence = 4, OccurredAtUtc = reached.AddMinutes(4) },
            scan,
            scan with { EventId = "scan-violation", EventType = "ProtocolViolation", Sequence = 2, OccurredAtUtc = reached.AddMinutes(1) },
            scan with { EventId = "scan-closed", ConnectionId = "SCAN", EventType = "SessionClosed", Sequence = 3, OccurredAtUtc = reached.AddMinutes(3) },
        })
            Assert.True((await store.AppendAsync(step)).Recorded);

        Assert.Equal(2, store.GetAll().Count);
        Assert.DoesNotContain(store.GetAll(), item => item.EventId == old.EventId);
        Assert.Equal(new[] { "auth-accepted", "auth-first", "auth-second", "auth-closed" },
            store.GetByConnectionId("AUTH").Select(item => item.EventId));

        var eventQuery = new InteractionEventQuery(SourceIp: accepted.SourceIp, AdapterKey: "SSH", EventType: "authenticationattempted",
            DestinationPort: accepted.DestinationPort, ConnectionIds: new HashSet<string>(StringComparer.Ordinal) { "auth" },
            Page: 2, PageSize: 1);
        var raw = store.ReadEvents(eventQuery);
        Assert.Equal(2, raw.Total);
        Assert.Equal("auth-first", Assert.Single(raw.Items).EventId);
        var activity = store.ReadActivities(eventQuery with { Page = 1, FromUtc = reached.AddMinutes(1), ToUtc = reached.AddMinutes(2) });
        Assert.Equal(1, activity.Total);
        var selected = Assert.Single(activity.Items);
        Assert.Equal("auth-first", selected.EventId);
        Assert.Equal(4, selected.EventCount);

        var projected = store.ReadActivities(new());
        Assert.Equal(4, projected.Total);
        Assert.Equal(3, Assert.Single(projected.Items, item => item.EventId == "scan-violation").EventCount);
        Assert.Equal("old-accepted", Assert.Single(store.ReadActivities(new(EventType: "ConnectionAccepted")).Items).EventId);

        var scanQuery = eventQuery with
        {
            SourceIp = scan.SourceIp, ConnectionIds = new HashSet<string>(StringComparer.Ordinal) { "scan" },
            EventType = " ", Page = int.MaxValue, PageSize = 100,
        };
        var outOfRange = store.ReadActivities(scanQuery);
        Assert.Equal(1, outOfRange.Total);
        Assert.Empty(outOfRange.Items);
        var exactCase = store.ReadActivities(scanQuery with { Page = 1 });
        Assert.Equal(2, Assert.Single(exactCase.Items).EventCount);
        var noMatch = store.ReadActivities(scanQuery with { ConnectionIds = new HashSet<string>(StringComparer.Ordinal) { "Scan" } });
        Assert.Equal(0, noMatch.Total);
        Assert.Empty(noMatch.Items);

        clock.Advance(TimeSpan.FromDays(2) - TimeSpan.FromHours(2));
        Assert.DoesNotContain(store.ReadEvents(new()).Items, item => item.EventId == old.EventId);
        Assert.Empty(store.GetByConnectionId(old.ConnectionId));
        Assert.Equal(7, store.ReadEvents(new()).Total);
        Assert.Equal(3, store.ReadActivities(new()).Total);
    }

    [Fact]
    public async Task MssqlProtocolErrorCodesSurviveStoreRestartInRawConnectionDetails()
    {
        await using var fixture = await Fixture.CreateAsync();
        var store = fixture.Store();
        (string Stage, string? ErrorCode)[] diagnostics =
        {
            ("prelogin", "TDS_PRELOGIN_INVALID"), ("tls", "TDS_TLS_FAILED"),
            ("login7", "TDS_LOGIN7_INVALID"), ("integrated-auth", "TDS_INTEGRATED_AUTH_INVALID"),
        };
        var template = Event("diagnostic", "ProtocolViolation", Start) with
        {
            AdapterKey = "mssql", ConnectionId = "mssql-diagnostic-test", Outcome = "failure",
        };
        for (var index = 0; index < diagnostics.Length; index++)
        {
            var (stage, code) = diagnostics[index];
            var step = template with { EventId = $"diagnostic-{index}", Sequence = index + 1, Stage = stage, ProtocolErrorCode = code };
            Assert.True((await store.AppendAsync(step)).Recorded);
        }
        var legacy = template with { EventId = "old-diagnostic", Sequence = 5, Stage = "handshake" };
        Assert.True((await store.AppendAsync(legacy)).Recorded);
        Assert.True((await store.AppendAsync(legacy with
        {
            EventId = "unrecognized-diagnostic", Sequence = 6, ProtocolErrorCode = "unrecognized diagnostic text",
        })).Recorded);

        store = await fixture.RecreateStoreAsync();
        var steps = store.GetByConnectionId(template.ConnectionId).ToArray();
        Assert.Equal(diagnostics, steps.Take(4).Select(step => (step.Stage, step.ProtocolErrorCode)).ToArray());
        Assert.Equal("handshake", steps[4].Stage);
        Assert.All(steps.Skip(4), step => Assert.Null(step.ProtocolErrorCode));
        var body = System.Text.Json.JsonSerializer.Serialize(steps, new System.Text.Json.JsonSerializerOptions(System.Text.Json.JsonSerializerDefaults.Web));
        Assert.Contains("\"protocolErrorCode\":\"TDS_TLS_FAILED\"", body);
        Assert.DoesNotContain("unrecognized diagnostic text", body);
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
    public async Task DatabaseFailureReturnsDegradedAndIsObservable()
    {
        await using var fixture = await Fixture.CreateAsync(createSchema: false);
        var store = fixture.Store();
        var result = await store.AppendAsync(Event("not-recorded", "ConnectionAccepted", Start));
        Assert.False(result.Recorded);
        Assert.True(result.Degraded);
        Assert.Equal("REPORT_PERSISTENCE_FAILED", result.Code);
        Assert.Equal(1, fixture.Health.PersistenceFailures);
        Assert.Throws<SqliteException>(() => store.GetAll());
    }

    [Fact]
    public async Task BoundedWriterAdmitsOnlyCapacityAndSkipsCancelledPendingEvent()
    {
        await using var fixture = await Fixture.CreateAsync();
        using var evidence = new InMemoryCredentialEvidenceStore();
        var settings = OptionsFactory.Create(new EventStorageOptions { QueueCapacity = 1 });
        var store = new ReportInteractionEventStore(fixture.Factory, evidence, fixture.Threats(), fixture.Health,
            NullLogger<ReportInteractionEventStore>.Instance, options: settings);
        using var cancellation = new CancellationTokenSource();
        var pending = store.AppendAsync(Event("pending", "ConnectionAccepted", Start), cancellation.Token).AsTask();
        Assert.Equal(1, fixture.Health.EventQueueDepth);
        Assert.Equal("REPORT_EVENT_QUEUE_FULL", (await store.AppendAsync(Event("full", "ConnectionAccepted", Start))).Code);
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => pending);

        using var worker = new ReportEventWriterWorker(store);
        await worker.StartAsync(CancellationToken.None);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(2));
        await worker.StopAsync(deadline.Token);
        await using var db = fixture.Factory.CreateDbContext();
        Assert.Equal(0, await db.Set<ReportEventEntity>().CountAsync());
        Assert.Equal(2, fixture.Health.RejectedEvents);
        Assert.Equal(0, fixture.Health.EventQueueDepth);
    }

    [Fact]
    public async Task LiveEventAndThreatViewsExpireAndReturnBoundedSnapshots()
    {
        var clock = new MutableTime(Start);
        var options = OptionsFactory.Create(new EventStorageOptions { MemoryEventCapacity = 2, MemoryRetentionHours = 1 });
        using var evidence = new InMemoryCredentialEvidenceStore();
        var threats = new InMemoryThreatProfileStore(2, TimeSpan.FromHours(1), clock);
        var store = new InMemoryInteractionEventStore(threats, evidence, options: options, time: clock);
        await store.AppendAsync(Event("one", "ConnectionAccepted", Start));
        var snapshot = threats.GetByIp("192.0.2.10")!;
        await store.AppendAsync(Event("two", "AuthenticationAttempted", Start) with
        {
            DestinationPort = 4444, Username = "\u0000" + new string('x', 200),
            AuthenticationMethod = "method\n" + new string('y', 120), Password = "isolated-test-password",
        });
        Assert.Single(snapshot.PortsTouched);
        Assert.Equal(2, threats.GetByIp("192.0.2.10")!.PortsTouched.Count);
        var bounded = Assert.Single(store.GetAll(), item => item.EventId == "two");
        Assert.Null(bounded.Password);
        Assert.DoesNotContain('\n', bounded.AuthenticationMethod!);
        Assert.InRange(bounded.AuthenticationMethod!.Length, 1, 64);
        Assert.DoesNotContain('\u0000', bounded.Username!);
        Assert.InRange(bounded.Username!.Length, 1, 128);

        await store.AppendAsync(Event("three", "ConnectionAccepted", Start) with { SourceIp = "192.0.2.11" });
        Assert.DoesNotContain(store.GetAll(), item => item.EventId == "one");
        await store.AppendAsync(Event("four", "ConnectionAccepted", Start) with { SourceIp = "192.0.2.12" });
        Assert.Null(threats.GetByIp("192.0.2.10"));
        clock.Advance(TimeSpan.FromHours(1));
        Assert.Empty(store.GetAll());
        Assert.Empty(threats.GetAll());
    }

    [Fact]
    public async Task RetentionDeletesExpiredFactsButPreservesFirstSeenForActiveSources()
    {
        await using var fixture = await Fixture.CreateAsync();
        var now = Start.AddDays(2);
        var clock = new FixedTime(now);
        var options = OptionsFactory.Create(new EventStorageOptions { ReportRetentionDays = 1 });
        var store = fixture.Store();
        await store.AppendAsync(Event("old-for-active-ip", "ConnectionAccepted", Start));
        await store.AppendAsync(Event("old-for-idle-ip", "ConnectionAccepted", Start) with { SourceIp = "192.0.2.11" });
        await store.AppendAsync(Event("retained", "ConnectionAccepted", now.AddHours(-1)));
        await fixture.SampleAsync(Start, Start.AddHours(1));
        await fixture.SampleAsync(now.AddHours(-1), now);

        using var worker = new ReportEventRetentionWorker(fixture.Factory, options, fixture.Health, clock, new(clock),
            NullLogger<ReportEventRetentionWorker>.Instance);
        await worker.RunOnceAsync(CancellationToken.None);
        await using var db = fixture.Factory.CreateDbContext();
        Assert.Equal("retained", (await db.Set<ReportEventEntity>().SingleAsync()).EventId);
        var source = await db.Set<ReportSourceFirstSeenEntity>().SingleAsync();
        Assert.Equal("192.0.2.10", source.SourceIp);
        Assert.Equal(Start.ToUnixTimeMilliseconds(), source.FirstSeenAtUnixMs);
        Assert.Equal(now.ToUnixTimeMilliseconds(), (await db.Set<ReportRuntimeSampleEntity>().SingleAsync()).CapturedAtUnixMs);
        var report = await new SqliteReportService(fixture.Factory, clock, storageOptions: options).GenerateAsync(new()
        {
            Period = "custom", StartAtUtc = Start, EndAtUtc = now,
        });
        Assert.Equal("partial", report.Coverage.Status);
        Assert.Equal(1, report.Totals.EventCount);
        Assert.Equal(0, report.Totals.NewSourceIps);
    }

    [Fact]
    public async Task DiskBudgetStopsSQLiteGrowthAndRetentionAllowsReuse()
    {
        var path = Path.Combine(Directory.CreateTempSubdirectory("honeypot-report-budget-").FullName, "budget.db");
        await using var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = path, Pooling = false }.ToString());
        await connection.OpenAsync();
        var factory = new Factory(new DbContextOptionsBuilder<HoneypotDbContext>().UseSqlite(connection).Options);
        await using (var setup = factory.CreateDbContext()) await setup.Database.EnsureCreatedAsync();

        // 利用正常报告事件与普通旧数据验证容量页限制，全部写入测试生成的独立文件。
        var clock = new FixedTime(Start.AddDays(2));
        var tightOptions = OptionsFactory.Create(new EventStorageOptions { DatabaseBudgetMiB = 8, MinimumFreeDiskMiB = 8, ReportRetentionDays = 1 });
        var health = new ReportIngestionHealth();
        var diskBudget = new ReportEventDiskBudget(clock);
        using var evidence = new InMemoryCredentialEvidenceStore();
        var threats = new SqliteThreatProfileStore(factory, tightOptions, clock, new ResourceIdGenerator());
        var store = new ReportInteractionEventStore(factory, evidence, threats, health,
            NullLogger<ReportInteractionEventStore>.Instance, options: tightOptions, time: clock, diskBudget: diskBudget);
        using var writer = new ReportEventWriterWorker(store);
        var now = clock.GetUtcNow();
        await writer.StartAsync(CancellationToken.None);
        try
        {
            await using var db = factory.CreateDbContext();
            var before = new FileInfo(path).Length;
            Assert.True((await store.AppendAsync(Event("limit-installed", "ConnectionAccepted", now))).Recorded);
            await using var pragma = connection.CreateCommand();
            pragma.CommandText = "PRAGMA page_size";
            var pageSize = (long)(await pragma.ExecuteScalarAsync())!;
            pragma.CommandText = "PRAGMA max_page_count";
            Assert.Equal((7 * 1024 * 1024) / pageSize, (long)(await pragma.ExecuteScalarAsync())!);
            Assert.True(health.DatabaseBytes >= before);

            await db.Database.ExecuteSqlInterpolatedAsync($"""
                INSERT INTO report_events ("EventId", "OccurredAtUnixMs", "EventType", "SourceIp", "AdapterKey", "DestinationPort",
                    "Username", "AuthenticationMethod", "IsAuthenticationFailure", "RiskSignal", "EvidenceKind", "CaptureTruncated")
                VALUES ('old', {Start.ToUnixTimeMilliseconds()}, 'authenticationattempted', '192.0.2.11', 'ssh', 22,
                    {new string('x', 6 * 1024 * 1024)}, 'password', 1, 'medium', 'none', 0)
                """);
            var highWater = new FileInfo(path).Length;
            var tooLarge = await Assert.ThrowsAsync<SqliteException>(() => db.Database.ExecuteSqlInterpolatedAsync($"""
                UPDATE report_events SET "Username"={new string('x', 8 * 1024 * 1024)} WHERE "EventId"='old'
                """));
            Assert.Equal(13, tooLarge.SqliteErrorCode);

            using var retention = new ReportEventRetentionWorker(factory, tightOptions, health, clock, diskBudget,
                NullLogger<ReportEventRetentionWorker>.Instance);
            await retention.RunOnceAsync(CancellationToken.None);
            pragma.CommandText = "PRAGMA freelist_count";
            Assert.True((long)(await pragma.ExecuteScalarAsync())! > 1_000);
            Assert.Equal(highWater, new FileInfo(path).Length);
            Assert.True((await store.AppendAsync(Event("after-retention", "ConnectionAccepted", now))).Recorded);
            Assert.Equal(highWater, new FileInfo(path).Length);

            // 模拟升级前已有的过大数据库，接纳失败时原有事件仍可查询。
            pragma.CommandText = "PRAGMA max_page_count = 100000";
            await pragma.ExecuteScalarAsync();
            await db.Database.ExecuteSqlInterpolatedAsync($"""
                UPDATE report_events SET "Username"={new string('x', 9 * 1024 * 1024)} WHERE "EventId"='after-retention'
                """);
            Assert.Equal("REPORT_DISK_BUDGET_EXCEEDED", (await store.AppendAsync(Event("over-budget", "ConnectionAccepted", now))).Code);
            Assert.True(health.DiskBudgetBlocked);
            Assert.Equal(2, await db.Set<ReportEventEntity>().CountAsync());
            Assert.DoesNotContain(store.GetAll(), item => item.EventId == "over-budget");
        }
        finally { await writer.StopAsync(CancellationToken.None); }
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

    private sealed class MutableTime(DateTimeOffset now) : TimeProvider
    {
        private long _elapsedTicks;
        public override DateTimeOffset GetUtcNow() => now.AddTicks(_elapsedTicks);
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override long GetTimestamp() => _elapsedTicks;
        public void Advance(TimeSpan duration) => _elapsedTicks += duration.Ticks;
    }

    private sealed class Factory(DbContextOptions<HoneypotDbContext> options) : IDbContextFactory<HoneypotDbContext>
    {
        public HoneypotDbContext CreateDbContext() => new(options);
    }

    private sealed class Fixture(SqliteConnection connection, Factory factory, TimeProvider time,
        IOptions<EventStorageOptions> options) : IAsyncDisposable
    {
        private readonly InMemoryCredentialEvidenceStore _evidence = new();
        private ReportInteractionEventStore? _store;
        private ReportEventWriterWorker? _writer;
        public Factory Factory { get; } = factory;
        public ReportIngestionHealth Health { get; } = new();
        public static async Task<Fixture> CreateAsync(bool createSchema = true, TimeProvider? time = null,
            EventStorageOptions? storage = null, string? databasePath = null)
        {
            var connection = new SqliteConnection(databasePath is null ? "Data Source=:memory:" :
                new SqliteConnectionStringBuilder { DataSource = databasePath, Pooling = false }.ToString());
            await connection.OpenAsync();
            var factory = new Factory(new DbContextOptionsBuilder<HoneypotDbContext>().UseSqlite(connection).Options);
            if (createSchema)
            {
                await using var db = factory.CreateDbContext();
                await db.Database.EnsureCreatedAsync();
            }
            return new(connection, factory, time ?? new FixedTime(Start), OptionsFactory.Create(storage ?? new()));
        }
        public SqliteThreatProfileStore Threats() => new(Factory, options, time, new ResourceIdGenerator());

        public ReportInteractionEventStore Store()
        {
            if (_store is not null) return _store;
            _store = new(Factory, _evidence, Threats(), Health,
                NullLogger<ReportInteractionEventStore>.Instance, options: options, time: time);
            _writer = new(_store);
            _writer.StartAsync(CancellationToken.None).GetAwaiter().GetResult();
            return _store;
        }

        public async Task<ReportInteractionEventStore> RecreateStoreAsync()
        {
            await StopWriterAsync();
            return Store();
        }
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
            await StopWriterAsync();
            _evidence.Dispose();
            await connection.DisposeAsync();
        }

        private async Task StopWriterAsync()
        {
            if (_writer is null) return;
            await _writer.StopAsync(CancellationToken.None);
            _writer.Dispose();
            _writer = null;
            _store = null;
        }
    }
}
