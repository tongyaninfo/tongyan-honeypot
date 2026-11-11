using System.Text.Json;
using Honeypot.Api.Common;
using Honeypot.Api.Data;
using Honeypot.Api.Data.Models;
using Honeypot.Api.Models;
using Honeypot.Api.Service;
using Honeypot.Api.Service.impl;
using Honeypot.Shared.Models;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Xunit;

namespace Honeypot.Runtime.Tests;

public sealed class NotificationTests
{
    [Fact]
    public void ValidationRejectsHeaderInjectionAndMismatchedTls()
    {
        Assert.Throws<NotificationException>(() => NotificationSettingsValidation.NormalizeAddress("safe@example.test\r\nBcc: other@example.test"));
        Assert.Throws<NotificationException>(() => NotificationSettingsValidation.Normalize(ValidSettings() with { UseSsl = true, SecurityMode = "None" }, true));
        Assert.Throws<NotificationException>(() => NotificationSettingsValidation.Normalize(ValidSettings() with { Schedules = [null!, new() { Kind = "Weekly" }, new() { Kind = "Monthly" }] }, true));
        Assert.Throws<NotificationException>(() => NotificationSettingsValidation.Normalize(ValidSettings() with { Host = null! }, true));
        Assert.Throws<NotificationException>(() => NotificationSettingsValidation.NormalizeRecipients([null!]));
    }

    [Fact]
    public async Task CredentialIsEncryptedAndSurvivesStoreRecreationWithoutReturningPlaintext()
    {
        var directory = Directory.CreateTempSubdirectory("honeypot-notification-test-").FullName;
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["Honeypot:DataDirectory"] = directory }).Build();
        var clock = new TestClock();
        var store = new FileNotificationSettingsStore(configuration, new TestEnvironment(), clock);
        const string syntheticCredential = "synthetic-authorization-for-unit-test";
        var saved = await store.SaveAsync(new(ValidSettings(), syntheticCredential));
        Assert.True(saved.HasCredential);
        var savedText = await File.ReadAllTextAsync(Path.Combine(directory, "notifications", "settings.json"));
        Assert.DoesNotContain(syntheticCredential, savedText, StringComparison.Ordinal);
        Assert.DoesNotContain(syntheticCredential, JsonSerializer.Serialize(saved), StringComparison.Ordinal);
        var restarted = new FileNotificationSettingsStore(configuration, new TestEnvironment(), clock);
        await restarted.SaveAsync(new(saved with { FromName = "新名称" }, ""));
        Assert.Equal(syntheticCredential, (await restarted.GetTransportAsync()).Credential);
        if (!OperatingSystem.IsWindows())
        {
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(Path.Combine(directory, "notifications", "keys", "smtp.key")));
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(Path.Combine(directory, "notifications", "settings.json")));
        }
        // 测试目录只包含合成数据，按项目约定不在测试中主动删除文件。
    }

    [Fact]
    public async Task MissingProtectionKeyDoesNotRegenerateOrOverwriteCredential()
    {
        var directory = Directory.CreateTempSubdirectory("honeypot-notification-missing-key-").FullName;
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["Honeypot:DataDirectory"] = directory }).Build();
        var store = new FileNotificationSettingsStore(configuration, new TestEnvironment(), new TestClock());
        await store.SaveAsync(new(ValidSettings(), "synthetic-credential"));
        var savedPath = Path.Combine(directory, "notifications", "settings.json");
        var before = await File.ReadAllTextAsync(savedPath);
        var missingKeyDirectory = Path.Combine(directory, "intentionally-missing-keys");
        var missingConfiguration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Honeypot:DataDirectory"] = directory, ["Honeypot:NotificationKeyDirectory"] = missingKeyDirectory
        }).Build();
        var restarted = new FileNotificationSettingsStore(missingConfiguration, new TestEnvironment(), new TestClock());
        var error = await Assert.ThrowsAsync<NotificationException>(() => restarted.GetTransportAsync());
        Assert.Equal("SMTP_PROTECTION_KEY_MISSING", error.Code);
        await Assert.ThrowsAsync<NotificationException>(() => restarted.SaveAsync(new(ValidSettings(), "replacement-synthetic-credential")));
        Assert.False(Directory.Exists(missingKeyDirectory));
        Assert.Equal(before, await File.ReadAllTextAsync(savedPath));
    }

    [Theory]
    [InlineData("Daily", "2026-11-10T00:00:00Z", "2026-11-08T16:00:00Z", "2026-11-09T16:00:00Z")]
    [InlineData("Weekly", "2026-11-09T00:00:00Z", "2026-11-01T16:00:00Z", "2026-11-08T16:00:00Z")]
    [InlineData("Monthly", "2026-11-01T00:00:00Z", "2026-09-30T16:00:00Z", "2026-10-31T16:00:00Z")]
    public void ScheduleUsesPreviousCompleteChinaCalendarPeriod(string kind, string at, string start, string end)
    {
        var period = NotificationScheduleCalculator.MostRecent(kind, "08:00", DateTimeOffset.Parse(at));
        Assert.Equal(DateTimeOffset.Parse(at), period.ScheduledAtUtc);
        Assert.Equal(DateTimeOffset.Parse(start), period.StartAtUtc);
        Assert.Equal(DateTimeOffset.Parse(end), period.EndAtUtc);
        Assert.True(NotificationScheduleCalculator.Next(kind, "08:00", DateTimeOffset.Parse(at)) > period.ScheduledAtUtc);
    }

    [Fact]
    public void HtmlTemplateEncodesAttackerInputAndIncludesCoverageAndPlainText()
    {
        var renderer = new EmailTemplateRenderer(new TestEnvironment { ContentRootPath = ApiDirectory() });
        var report = SampleReport() with { Sources = [new("<img src=x onerror=alert(1)>", 1, 1, 1, 1)], MailSummary = new(3, 1, 2, 0) };
        var rendered = renderer.RenderReport("Daily", report);
        Assert.DoesNotContain("<img", rendered.HtmlBody, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("&lt;img", rendered.HtmlBody, StringComparison.Ordinal);
        Assert.Contains("部分时段未覆盖", rendered.HtmlBody, StringComparison.Ordinal);
        Assert.Contains("SMTP 已受理", rendered.HtmlBody, StringComparison.Ordinal);
        Assert.DoesNotContain("{{", rendered.HtmlBody, StringComparison.Ordinal);
        Assert.DoesNotContain("<script", rendered.HtmlBody, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("连接次数", rendered.TextBody, StringComparison.Ordinal);
    }

    [Fact]
    public void ReportTemplatePreservesPartialCoverageAndMetricMeanings()
    {
        var renderer = new EmailTemplateRenderer(new TestEnvironment { ContentRootPath = ApiDirectory() });
        var report = SampleReport();
        report = report with
        {
            Coverage = report.Coverage with { CoveragePercent = 99.99, UnknownSeconds = 8.64 },
            Usernames = [new("test-user", 7, 0, 6, 2)],
            AuthenticationMethods = [new("password", 8, 0, 8, 2)],
            RiskSignals = [new("high", 12, 0, 0, 3)],
            Evidence = [new("Response", 4, 0, 0, 2)],
            Runtime = report.Runtime with { AverageProcessMemoryBytes = 512L * 1024 * 1024, MinimumDataDiskFreeBytes = 128L * 1024 * 1024 * 1024 }
        };
        var rendered = renderer.RenderReport("Daily", report);
        Assert.Contains("覆盖率 >99.9% · 未覆盖 少于1分钟", rendered.TextBody, StringComparison.Ordinal);
        Assert.DoesNotContain("未覆盖 0.0 小时", rendered.TextBody, StringComparison.Ordinal);
        Assert.Contains("test-user: 认证尝试 7 / 认证失败 6 / 来源 IP 2", rendered.TextBody, StringComparison.Ordinal);
        Assert.Contains("password: 认证尝试 8 / 认证失败 8 / 来源 IP 2", rendered.TextBody, StringComparison.Ordinal);
        Assert.Contains("high: 事件数 12 / 来源 IP 3", rendered.TextBody, StringComparison.Ordinal);
        Assert.Contains("Response: 关联事件数 4 / 来源 IP 2", rendered.TextBody, StringComparison.Ordinal);
        Assert.Contains("监听器采样正常比例", rendered.HtmlBody, StringComparison.Ordinal);
        Assert.Contains("512.0 MiB", rendered.TextBody, StringComparison.Ordinal);
        Assert.Contains("128.0 GiB", rendered.TextBody, StringComparison.Ordinal);
        var exactBoundary = renderer.RenderReport("Daily", report with { Coverage = report.Coverage with { CoveragePercent = 99.9 } });
        Assert.Contains("覆盖率 99.9%", exactBoundary.TextBody, StringComparison.Ordinal);
        Assert.DoesNotContain("覆盖率 >99.9%", exactBoundary.TextBody, StringComparison.Ordinal);
        foreach (var roundedBoundary in new[] { 99.95, 100d })
        {
            var partialBoundary = renderer.RenderReport("Daily", report with { Coverage = report.Coverage with { CoveragePercent = roundedBoundary } });
            Assert.Contains("覆盖率 >99.9%", partialBoundary.TextBody, StringComparison.Ordinal);
            Assert.DoesNotContain("覆盖率 100.0%", partialBoundary.TextBody, StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task AcceptedDeliveryFreezesBodyAndPersistsAttempt()
    {
        await using var fixture = await Fixture.CreateAsync();
        var queued = await fixture.Service.QueueReportAsync(new() { Period = "day", Recipients = ["reader@example.test"] }, "admin");
        await fixture.Service.ProcessPendingAsync();
        var details = await fixture.Service.GetDeliveryAsync(queued.DeliveryIds.Single());
        Assert.NotNull(details);
        Assert.Equal("Accepted", details.Delivery.Status);
        Assert.Equal(1, details.Delivery.AttemptCount);
        Assert.Single(details.Attempts);
        Assert.Equal("Accepted", details.Attempts[0].Outcome);
        Assert.False(details.CanRetry);
        Assert.NotNull(await fixture.Service.GetReportAsync(details.Delivery.ReportId!));
        await Assert.ThrowsAsync<NotificationException>(() => fixture.Service.RetryAsync(details.Delivery.Id, "admin"));
    }

    [Fact]
    public async Task UnknownResultIsNotAutomaticallyRetried()
    {
        await using var fixture = await Fixture.CreateAsync();
        fixture.Transport.Results.Enqueue(new("Unknown", "SMTP_RESULT_UNKNOWN", "结果不确定"));
        var queued = await fixture.Service.QueueTestAsync(new("reader@example.test"), "admin");
        await fixture.Service.ProcessPendingAsync();
        fixture.Clock.Advance(TimeSpan.FromHours(1));
        await fixture.Service.ProcessPendingAsync();
        Assert.Single(fixture.Transport.Sent);
        Assert.Equal("Unknown", (await fixture.Service.GetDeliveryAsync(queued.DeliveryIds[0]))!.Delivery.Status);
        await fixture.Service.RetryAsync(queued.DeliveryIds[0], "admin");
        await fixture.Service.ProcessPendingAsync();
        Assert.Equal(2, fixture.Transport.Sent.Count);
        Assert.Equal(fixture.Transport.Sent[0].MessageId, fixture.Transport.Sent[1].MessageId);
    }

    [Fact]
    public async Task TemporaryFailuresHaveBoundedRetriesAndManualRetryStartsNewBudget()
    {
        await using var fixture = await Fixture.CreateAsync();
        for (var i = 0; i < 4; i++) fixture.Transport.Results.Enqueue(new("Retrying", "SMTP_TEMPORARY_REJECTION", "临时拒绝"));
        var queued = await fixture.Service.QueueTestAsync(new("reader@example.test"), "admin");
        await fixture.Service.ProcessPendingAsync();
        fixture.Clock.Advance(TimeSpan.FromMinutes(1));
        await fixture.Service.ProcessPendingAsync();
        fixture.Clock.Advance(TimeSpan.FromMinutes(5));
        await fixture.Service.ProcessPendingAsync();
        Assert.Equal("Failed", (await fixture.Service.GetDeliveryAsync(queued.DeliveryIds[0]))!.Delivery.Status);
        fixture.Clock.Advance(TimeSpan.FromMinutes(1));
        await fixture.Service.RetryAsync(queued.DeliveryIds[0], "admin");
        await fixture.Service.ProcessPendingAsync();
        Assert.Equal("Retrying", (await fixture.Service.GetDeliveryAsync(queued.DeliveryIds[0]))!.Delivery.Status);
    }

    [Fact]
    public async Task RecipientQuotaAndTestCooldownSurviveServiceRecreation()
    {
        await using var fixture = await Fixture.CreateAsync();
        fixture.Settings.Value = ValidSettings() with { MaxPerRecipientPerHour = 1 };
        await fixture.Service.QueueTestAsync(new("Reader@example.test"), "admin");
        await fixture.Service.ProcessPendingAsync();
        var restarted = fixture.CreateService();
        var cooldown = await Assert.ThrowsAsync<NotificationException>(() => restarted.QueueTestAsync(new("another@example.test"), "admin"));
        Assert.Equal("RATE_LIMITED", cooldown.Code);
        fixture.Clock.Advance(TimeSpan.FromMinutes(2));
        var queued = await restarted.QueueTestAsync(new("reader@example.test"), "admin");
        await restarted.ProcessPendingAsync();
        Assert.Single(fixture.Transport.Sent);
        var details = await restarted.GetDeliveryAsync(queued.DeliveryIds[0]);
        Assert.Equal("Pending", details!.Delivery.Status);
        Assert.Equal("RATE_LIMITED", details.Delivery.LastErrorCode);
    }

    [Fact]
    public async Task ExpiredSendingBecomesUnknownWhileActiveLeaseIsPreserved()
    {
        await using var fixture = await Fixture.CreateAsync();
        var queued = await fixture.Service.QueueReportAsync(new() { Period = "day", Recipients = ["one@example.test", "two@example.test"] }, "admin");
        await using (var db = fixture.Factory.CreateDbContext())
        {
            var rows = await db.Set<EmailDeliveryEntity>().OrderBy(row => row.Recipient).ToArrayAsync();
            rows[0].Status = "Sending";
            rows[0].LeaseExpiresUnixMs = fixture.Clock.GetUtcNow().AddSeconds(-1).ToUnixTimeMilliseconds();
            rows[1].Status = "Sending";
            rows[1].LeaseExpiresUnixMs = fixture.Clock.GetUtcNow().AddMinutes(5).ToUnixTimeMilliseconds();
            await db.SaveChangesAsync();
        }
        await fixture.Service.ProcessPendingAsync();
        Assert.Equal("Unknown", (await fixture.Service.GetDeliveryAsync(queued.DeliveryIds[0]))!.Delivery.Status);
        Assert.Equal("Sending", (await fixture.Service.GetDeliveryAsync(queued.DeliveryIds[1]))!.Delivery.Status);
        Assert.Empty(fixture.Transport.Sent);
    }

    [Fact]
    public async Task SchedulerSkipsBeforeActivationAndOnlyCatchesLatestPeriodOnce()
    {
        await using var fixture = await Fixture.CreateAsync();
        fixture.Clock.Now = DateTimeOffset.Parse("2026-11-10T01:00:00Z");
        fixture.Settings.Value = ValidSettings() with { Schedules = [new() { Kind = "Daily", Enabled = true }, new() { Kind = "Weekly" }, new() { Kind = "Monthly" }] };
        fixture.Settings.ActivatedAtUtc = fixture.Clock.Now;
        await fixture.Service.ScheduleDueReportsAsync();
        Assert.Equal(0, (await fixture.Service.GetReportsAsync(1, 20, null)).Total);
        fixture.Clock.Advance(TimeSpan.FromDays(10));
        await fixture.Service.ScheduleDueReportsAsync();
        var restarted = fixture.CreateService();
        await restarted.ScheduleDueReportsAsync();
        var history = await restarted.GetReportsAsync(1, 20, null);
        Assert.Equal(1, history.Total);
        Assert.Equal(DateTimeOffset.Parse("2026-11-18T16:00:00Z"), history.Items[0].StartAtUtc);
        Assert.Equal(DateTimeOffset.Parse("2026-11-19T16:00:00Z"), history.Items[0].EndAtUtc);
    }

    private static NotificationSettings ValidSettings() => new()
    {
        Enabled = true, Host = "smtp.example.test", FromEmail = "sender@example.test", Username = "sender@example.test", HasCredential = true,
        DefaultRecipients = ["reader@example.test"]
    };

    private static OperationReport SampleReport() => new(
        DateTimeOffset.Parse("2026-11-10T00:00:00Z"),
        new("day", "Asia/Shanghai", DateTimeOffset.Parse("2026-11-08T16:00:00Z"), DateTimeOffset.Parse("2026-11-09T16:00:00Z"), "hour", false),
        new("partial", 80000, 6400, 92.6, null, null, 0, true),
        new(20, 5, 2, 1, 3, 3, 1, 3, 0),
        new(DateTimeOffset.Parse("2026-11-07T16:00:00Z"), DateTimeOffset.Parse("2026-11-08T16:00:00Z"), "unknown", new(null, null, null, null, null, null, null, null, null), null, null, null),
        [], [], [], [], [], [], [], [], new(10, 1, 2, 1000, 2000, 3, 2, 0, 2, 100, null), ["测试合成统计数据"]);

    private static string ApiDirectory() => Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../../src/Honeypot.Api"));

    private sealed class TestClock : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = DateTimeOffset.Parse("2026-11-10T00:00:00Z");
        public override DateTimeOffset GetUtcNow() => Now;
        public void Advance(TimeSpan value) => Now += value;
    }
    private sealed class TestIds : IResourceIdGenerator
    {
        private long _next;
        public string NewId() => "test-" + Interlocked.Increment(ref _next).ToString("D8");
    }
    private sealed class TestEnvironment : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = "Test";
        public string ApplicationName { get; set; } = "Honeypot.Api";
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
    private sealed class TestSettings : INotificationSettingsStore
    {
        public NotificationSettings Value { get; set; } = ValidSettings();
        public DateTimeOffset ActivatedAtUtc { get; set; } = DateTimeOffset.MinValue;
        public Task<NotificationSettings> GetAsync(CancellationToken cancellationToken = default) => Task.FromResult(Value);
        public Task<NotificationSettings> SaveAsync(UpdateNotificationSettingsRequest request, CancellationToken cancellationToken = default) => Task.FromResult(Value = request.Settings);
        public Task<NotificationTransportSettings> GetTransportAsync(CancellationToken cancellationToken = default) => Task.FromResult(new NotificationTransportSettings(Value.Enabled, Value.Host, Value.Port, Value.SecurityMode, Value.FromEmail, Value.FromName, Value.Username, "synthetic-only", 15));
        public Task<IReadOnlyList<NotificationScheduleState>> GetScheduleStatesAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<NotificationScheduleState>>(Value.Schedules.Where(row => Value.Enabled && row.Enabled).Select(row => new NotificationScheduleState(row, ActivatedAtUtc)).ToArray());
        public Task RecordScheduleRunAsync(string kind, DateTimeOffset? scheduledAtUtc, string status, CancellationToken cancellationToken = default)
        {
            Value = Value with { Schedules = Value.Schedules.Select(row => row.Kind == kind ? row with { LastRunAtUtc = scheduledAtUtc ?? row.LastRunAtUtc, LastRunStatus = status } : row).ToArray() };
            return Task.CompletedTask;
        }
    }
    private sealed class TestTransport : IMailTransport
    {
        public Queue<MailTransportResult> Results { get; } = new();
        public List<MailTransportMessage> Sent { get; } = [];
        public Task<MailTransportResult> SendAsync(NotificationTransportSettings settings, MailTransportMessage message, CancellationToken cancellationToken = default)
        {
            Sent.Add(message);
            return Task.FromResult(Results.Count > 0 ? Results.Dequeue() : MailTransportResult.Accepted);
        }
    }
    private sealed class TestReports : IReportService
    {
        public Task<OperationReport> GenerateAsync(ReportQuery query, CancellationToken cancellationToken = default)
        {
            var report = SampleReport();
            return Task.FromResult(query.StartAtUtc.HasValue && query.EndAtUtc.HasValue ? report with
            { Period = report.Period with { StartAtUtc = query.StartAtUtc.Value, EndAtUtc = query.EndAtUtc.Value } } : report);
        }
    }
    private sealed class TestFactory(DbContextOptions<HoneypotDbContext> options) : IDbContextFactory<HoneypotDbContext>
    {
        public HoneypotDbContext CreateDbContext() => new(options);
    }
    private sealed class Fixture : IAsyncDisposable
    {
        private readonly SqliteConnection _connection;
        private readonly TestIds _ids = new();
        public TestClock Clock { get; } = new();
        public TestSettings Settings { get; } = new();
        public TestTransport Transport { get; } = new();
        public TestFactory Factory { get; }
        public NotificationMailService Service { get; }
        private Fixture(SqliteConnection connection)
        {
            _connection = connection;
            Factory = new(new DbContextOptionsBuilder<HoneypotDbContext>().UseSqlite(connection).Options);
            Service = CreateService();
        }
        public NotificationMailService CreateService() => new(Factory, Settings, new TestReports(),
            new EmailTemplateRenderer(new TestEnvironment { ContentRootPath = ApiDirectory() }), Transport, _ids, Clock);
        public static async Task<Fixture> CreateAsync()
        {
            var connection = new SqliteConnection("Data Source=:memory:");
            await connection.OpenAsync();
            var fixture = new Fixture(connection);
            await using var db = fixture.Factory.CreateDbContext();
            await db.Database.EnsureCreatedAsync();
            return fixture;
        }
        public ValueTask DisposeAsync() => _connection.DisposeAsync();
    }
}
