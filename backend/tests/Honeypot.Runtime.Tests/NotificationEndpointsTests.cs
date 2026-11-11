using System.Net;
using System.Net.Http.Json;
using System.Text;
using Honeypot.Api.Common;
using Honeypot.Api.Models;
using Honeypot.Api.Service;
using Honeypot.Api.Service.impl;
using Honeypot.Shared.Models;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Xunit;

namespace Honeypot.Runtime.Tests;

public sealed class NotificationEndpointsTests
{
    [Fact]
    public async Task ServerEnforcesRolesAndReturnsUniformErrorsBeforeAnySend()
    {
        await using var fixture = await EndpointFixture.StartAsync();
        var client = fixture.Client;
        foreach (var path in new[] { "/api/v1/settings/notifications", "/api/v1/reports", "/api/v1/notifications/emails" })
        {
            var response = await client.GetAsync(path);
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.Contains("UNAUTHORIZED", await response.Content.ReadAsStringAsync());
        }
        client.DefaultRequestHeaders.Add("X-Test-Role", "viewer");
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/api/v1/reports?period=day")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await client.GetAsync("/api/v1/settings/notifications")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await client.GetAsync("/api/v1/reports/history")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await client.PostAsJsonAsync("/api/v1/notifications/test", new { recipient = "recipient@example.invalid" })).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await client.PostAsJsonAsync("/api/v1/reports/send", new { period = "day" })).StatusCode);
        Assert.Equal(0, fixture.Mail.Queued);
    }

    [Fact]
    public async Task InvalidBodiesAndQueriesAreBoundedAndNeverReachTheQueue()
    {
        await using var fixture = await EndpointFixture.StartAsync();
        var client = fixture.Client;
        client.DefaultRequestHeaders.Add("X-Test-Role", "Administrator");
        foreach (var body in new[] { "{", "null", "", new string('x', 33000) })
        {
            var response = await client.PostAsync("/api/v1/notifications/test", new StringContent(body, Encoding.UTF8, "application/json"));
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.Contains("VALIDATION_ERROR", await response.Content.ReadAsStringAsync());
        }
        foreach (var path in new[]
        {
            "/api/v1/notifications/emails?page=0", "/api/v1/notifications/emails?pageSize=101",
            "/api/v1/notifications/emails?fromUtc=2026-11-10T00:00:00",
            "/api/v1/notifications/emails?fromUtc=2026-11-10T00:00:00Z&toUtc=2026-11-09T00:00:00Z",
            "/api/v1/reports?period=year", "/api/v1/reports?period=custom",
            "/api/v1/reports?period=custom&startAtUtc=2026-11-10&endAtUtc=2026-11-11",
            "/api/v1/reports/history?pageSize=0",
        })
            Assert.Equal(HttpStatusCode.BadRequest, (await client.GetAsync(path)).StatusCode);
        Assert.Equal(0, fixture.Mail.Queued);
    }

    [Fact]
    public async Task AcceptedMeansQueuedAndFailuresKeepTheirHttpStatus()
    {
        await using var fixture = await EndpointFixture.StartAsync();
        var client = fixture.Client;
        client.DefaultRequestHeaders.Add("X-Test-Role", "Administrator");
        var queued = await client.PostAsJsonAsync("/api/v1/notifications/test", new { recipient = "recipient@example.invalid" });
        Assert.Equal(HttpStatusCode.Accepted, queued.StatusCode);
        Assert.True(queued.Headers.CacheControl?.NoStore);
        var result = await queued.Content.ReadFromJsonAsync<ApiResult<NotificationTaskResult>>();
        Assert.True(result!.Success);
        Assert.Equal("mail1", Assert.Single(result.Data!.DeliveryIds));
        var limited = await client.PostAsJsonAsync("/api/v1/notifications/test", new { recipient = "limited@example.invalid" });
        Assert.Equal(HttpStatusCode.TooManyRequests, limited.StatusCode);
        Assert.Contains("RATE_LIMITED", await limited.Content.ReadAsStringAsync());
        Assert.Equal(HttpStatusCode.NotFound, (await client.GetAsync("/api/v1/notifications/emails/missing")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await client.GetAsync("/api/v1/reports/history/missing")).StatusCode);
        Assert.Equal(1, fixture.Mail.Queued);
    }

    [Fact]
    public async Task SettingsContractNeverEchoesTheSubmittedAuthorizationCode()
    {
        await using var fixture = await EndpointFixture.StartAsync();
        fixture.Client.DefaultRequestHeaders.Add("X-Test-Role", "Administrator");
        var response = await fixture.Client.PutAsJsonAsync("/api/v1/settings/notifications", new UpdateNotificationSettingsRequest(new(), "isolated-test-credential"));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.DoesNotContain("isolated-test-credential", body);
        Assert.DoesNotContain("authorizationCode", body);
        var settings = await response.Content.ReadFromJsonAsync<ApiResult<NotificationSettings>>();
        Assert.True(settings!.Data!.HasCredential);
    }

    private sealed class EndpointFixture(WebApplication app, HttpClient client, FakeMail mail) : IAsyncDisposable
    {
        public HttpClient Client => client;
        public FakeMail Mail => mail;
        public static async Task<EndpointFixture> StartAsync()
        {
            var builder = WebApplication.CreateBuilder();
            builder.Logging.ClearProviders();
            // 仅回环临时端口，使用替身服务，绝不连接真实 SMTP 或现有数据库。
            builder.WebHost.UseUrls("http://127.0.0.1:0");
            var mail = new FakeMail();
            builder.Services.AddSingleton<INotificationMailService>(mail);
            builder.Services.AddSingleton<INotificationSettingsStore, FakeSettings>();
            builder.Services.AddSingleton<IReportService, FakeReport>();
            var app = builder.Build();
            app.Use((context, next) =>
            {
                if (context.Request.Headers["X-Test-Role"].FirstOrDefault() is { } role)
                    context.Items["CurrentUser"] = new AuthenticatedUser("test-user", "test", [role]);
                return next(context);
            });
            app.MapNotificationEndpoints();
            await app.StartAsync();
            return new(app, new HttpClient { BaseAddress = new Uri(app.Urls.Single()) }, mail);
        }
        public async ValueTask DisposeAsync()
        {
            client.Dispose();
            await app.StopAsync();
            await app.DisposeAsync();
        }
    }

    private sealed class FakeSettings : INotificationSettingsStore
    {
        private NotificationSettings _settings = new();
        public Task<NotificationSettings> GetAsync(CancellationToken cancellationToken = default) => Task.FromResult(_settings);
        public Task<NotificationSettings> SaveAsync(UpdateNotificationSettingsRequest request, CancellationToken cancellationToken = default)
        {
            _settings = NotificationSettingsValidation.Normalize(request.Settings, !string.IsNullOrEmpty(request.AuthorizationCode));
            return Task.FromResult(_settings);
        }
        public Task<NotificationTransportSettings> GetTransportAsync(CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<IReadOnlyList<NotificationScheduleState>> GetScheduleStatesAsync(CancellationToken cancellationToken = default) => Task.FromResult<IReadOnlyList<NotificationScheduleState>>([]);
        public Task RecordScheduleRunAsync(string kind, DateTimeOffset? scheduledAtUtc, string status, CancellationToken cancellationToken = default) => Task.CompletedTask;
    }

    private sealed class FakeMail : INotificationMailService
    {
        public int Queued { get; private set; }
        public Task<NotificationTaskResult> QueueTestAsync(TestEmailRequest request, string requestedBy, CancellationToken cancellationToken = default)
        {
            if (request.Recipient == "limited@example.invalid") throw new NotificationException("RATE_LIMITED", "测试发送过于频繁。");
            Queued++;
            return Task.FromResult(new NotificationTaskResult(["mail1"], "已排队"));
        }
        public Task<NotificationTaskResult> QueueReportAsync(ReportSendRequest request, string requestedBy, CancellationToken cancellationToken = default) => Task.FromResult(new NotificationTaskResult(["mail1"], "已排队"));
        public Task<NotificationTaskResult> RetryAsync(string id, string requestedBy, CancellationToken cancellationToken = default) => Task.FromResult(new NotificationTaskResult([id], "已排队"));
        public Task<NotificationPage<EmailDeliverySummary>> GetDeliveriesAsync(EmailDeliveryQuery query, CancellationToken cancellationToken = default) => Task.FromResult(new NotificationPage<EmailDeliverySummary>([], 0, query.Page, query.PageSize));
        public Task<EmailDeliveryDetails?> GetDeliveryAsync(string id, CancellationToken cancellationToken = default) => Task.FromResult<EmailDeliveryDetails?>(null);
        public Task<NotificationPage<ReportHistoryItem>> GetReportsAsync(int page, int pageSize, string? kind, CancellationToken cancellationToken = default) => Task.FromResult(new NotificationPage<ReportHistoryItem>([], 0, page, pageSize));
        public Task<OperationReport?> GetReportAsync(string id, CancellationToken cancellationToken = default) => Task.FromResult<OperationReport?>(null);
        public Task ProcessPendingAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task ScheduleDueReportsAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
    }

    private sealed class FakeReport : IReportService
    {
        public Task<OperationReport> GenerateAsync(ReportQuery query, CancellationToken cancellationToken = default)
        {
            var now = new DateTimeOffset(2026, 11, 10, 12, 0, 0, TimeSpan.Zero);
            var (period, start, end) = SqliteReportService.ResolvePeriod(query, now);
            var totals = new ReportTotals(null, null, null, null, null, null, null, null, null);
            return Task.FromResult(new OperationReport(now, period, new("unknown", 0, 86400, 0, null, null, 0, false), totals,
                new(start, end, "unknown", totals, null, null, null), [], [], [], [], [], [], [], [],
                new(0, null, null, null, null, null, null, null, null, null, null), []));
        }
    }
}
