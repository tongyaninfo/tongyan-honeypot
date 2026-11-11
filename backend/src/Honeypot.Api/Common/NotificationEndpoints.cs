using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using Honeypot.Api.Models;
using Honeypot.Api.Service;
using Honeypot.Shared.Models;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace Honeypot.Api.Common;

/// <summary>报告通知管理入口；授权、参数上限及统一失败响应均在服务端执行。</summary>
public static class NotificationEndpoints
{
    private const int MaximumBodyBytes = 32 * 1024;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web) { MaxDepth = 12 };

    public static void MapNotificationEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/api/v1/settings/notifications", (HttpContext context, INotificationSettingsStore settings) =>
            ExecuteAsync(context, true, async () => Results.Ok(ApiResult<NotificationSettings>.Ok(await settings.GetAsync(context.RequestAborted)))));

        endpoints.MapPut("/api/v1/settings/notifications", (HttpContext context, INotificationSettingsStore settings) =>
            ExecuteAsync(context, true, async () =>
            {
                var request = await ReadBodyAsync<UpdateNotificationSettingsRequest>(context);
                if (request?.Settings is null) return Invalid("请提供有效的邮件与报告设置。");
                return Results.Ok(ApiResult<NotificationSettings>.Ok(await settings.SaveAsync(request, context.RequestAborted)));
            }));

        endpoints.MapPost("/api/v1/notifications/test", (HttpContext context, INotificationMailService mail) =>
            ExecuteAsync(context, true, async () =>
            {
                var request = await ReadBodyAsync<TestEmailRequest>(context);
                if (request is null) return Invalid("请提供测试收件人。");
                return Queued(await mail.QueueTestAsync(request, CurrentUserId(context), context.RequestAborted));
            }));

        endpoints.MapGet("/api/v1/notifications/emails", (HttpContext context, INotificationMailService mail) =>
            ExecuteAsync(context, true, async () =>
            {
                var query = context.Request.Query;
                var request = new EmailDeliveryQuery
                {
                    Page = PageNumber(query["page"], 1, int.MaxValue),
                    PageSize = PageNumber(query["pageSize"], 20, 100),
                    Kind = Filter(query["kind"], 32), Status = Filter(query["status"], 32),
                    Recipient = Filter(query["recipient"], 254),
                    FromUtc = ReadDate(query["fromUtc"]), ToUtc = ReadDate(query["toUtc"]),
                };
                if (request.FromUtc >= request.ToUtc) return Invalid("筛选开始时间必须早于结束时间。");
                return Results.Ok(ApiResult<NotificationPage<EmailDeliverySummary>>.Ok(await mail.GetDeliveriesAsync(request, context.RequestAborted)));
            }));

        endpoints.MapGet("/api/v1/notifications/emails/{id}", (string id, HttpContext context, INotificationMailService mail) =>
            ExecuteAsync(context, true, async () =>
            {
                if (!ValidId(id)) return Invalid("邮件记录编号无效。");
                var result = await mail.GetDeliveryAsync(id, context.RequestAborted);
                return result is null ? Missing("邮件记录不存在。") : Results.Ok(ApiResult<EmailDeliveryDetails>.Ok(result));
            }));

        endpoints.MapPost("/api/v1/notifications/emails/{id}/retry", (string id, HttpContext context, INotificationMailService mail) =>
            ExecuteAsync(context, true, async () => !ValidId(id) ? Invalid("邮件记录编号无效。") :
                Queued(await mail.RetryAsync(id, CurrentUserId(context), context.RequestAborted))));

        endpoints.MapGet("/api/v1/reports", (HttpContext context, IReportService reports) =>
            ExecuteAsync(context, false, async () =>
            {
                var query = context.Request.Query;
                var request = new ReportQuery
                {
                    Period = Filter(query["period"], 16) ?? "day",
                    StartAtUtc = ReadDate(query["startAtUtc"]), EndAtUtc = ReadDate(query["endAtUtc"]),
                };
                return Results.Ok(ApiResult<OperationReport>.Ok(await reports.GenerateAsync(request, context.RequestAborted)));
            }));

        endpoints.MapPost("/api/v1/reports/send", (HttpContext context, INotificationMailService mail) =>
            ExecuteAsync(context, true, async () =>
            {
                var request = await ReadBodyAsync<ReportSendRequest>(context);
                if (request is null) return Invalid("请提供报告周期与收件人。");
                return Queued(await mail.QueueReportAsync(request, CurrentUserId(context), context.RequestAborted));
            }));

        endpoints.MapGet("/api/v1/reports/history", (HttpContext context, INotificationMailService mail) =>
            ExecuteAsync(context, true, async () =>
            {
                var query = context.Request.Query;
                var page = PageNumber(query["page"], 1, int.MaxValue);
                var size = PageNumber(query["pageSize"], 20, 100);
                return Results.Ok(ApiResult<NotificationPage<ReportHistoryItem>>.Ok(await mail.GetReportsAsync(page, size, Filter(query["kind"], 32), context.RequestAborted)));
            }));

        endpoints.MapGet("/api/v1/reports/history/{id}", (string id, HttpContext context, INotificationMailService mail) =>
            ExecuteAsync(context, true, async () =>
            {
                if (!ValidId(id)) return Invalid("报告编号无效。");
                var result = await mail.GetReportAsync(id, context.RequestAborted);
                return result is null ? Missing("报告不存在。") : Results.Ok(ApiResult<OperationReport>.Ok(result));
            }));
    }

    private static async Task<IResult> ExecuteAsync(HttpContext context, bool administrator, Func<Task<IResult>> action)
    {
        context.Response.Headers.CacheControl = "no-store";
        if (context.Items["CurrentUser"] is not AuthenticatedUser user)
            return Error(401, "UNAUTHORIZED", "请先登录。");
        if (administrator && !UserAuthorization.IsAdministrator(user))
            return Error(403, "FORBIDDEN", "仅管理员可管理报告通知和邮件记录。");
        try { return await action(); }
        catch (NotificationException error)
        {
            var status = error.Code switch
            {
                "NOT_FOUND" => 404, "RATE_LIMITED" => 429,
                "CONFIG_UNAVAILABLE" or "CREDENTIAL_UNAVAILABLE" or "NOTIFICATION_CONFIGURATION_UNAVAILABLE" or
                    "NOTIFICATION_CONFIGURATION_WRITE_FAILED" or "SMTP_CREDENTIAL_UNAVAILABLE" or
                    "SMTP_PROTECTION_KEY_MISSING" or "SMTP_PROTECTION_KEY_INVALID" or "SMTP_PROTECTION_KEY_UNAVAILABLE" => 503,
                "CONFLICT" => 409, _ => 400,
            };
            // NotificationException 只允许业务层构造的受控中文提示，不传递 SMTP 异常正文。
            return Error(status, error.Code, error.Message);
        }
        catch (ArgumentException) { return Invalid("参数无效，请检查日期区间、邮箱、端口及报告设置。"); }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or CryptographicException or DbUpdateException or SqliteException)
        {
            context.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("NotificationEndpoints")
                .LogWarning("报告通知存储暂不可用，请检查数据目录、数据库和密钥可用性。");
            return Error(503, "NOTIFICATION_STORAGE_UNAVAILABLE", "报告通知存储暂不可用，请检查服务器数据目录与密钥配置。");
        }
    }

    private static async Task<T?> ReadBodyAsync<T>(HttpContext context) where T : class
    {
        if (!context.Request.HasJsonContentType() || context.Request.ContentLength > MaximumBodyBytes) return null;
        try
        {
            using var buffer = new MemoryStream();
            var chunk = new byte[4096];
            while (true)
            {
                var count = await context.Request.Body.ReadAsync(chunk, context.RequestAborted);
                if (count == 0) break;
                if (buffer.Length + count > MaximumBodyBytes) return null;
                buffer.Write(chunk, 0, count);
            }
            if (typeof(T) == typeof(ReportSendRequest))
            {
                using var document = JsonDocument.Parse(buffer.GetBuffer().AsMemory(0, (int)buffer.Length));
                if (document.RootElement.ValueKind != JsonValueKind.Object) return null;
                foreach (var name in new[] { "startAtUtc", "endAtUtc" })
                {
                    if (document.RootElement.TryGetProperty(name, out var date) && date.ValueKind != JsonValueKind.Null)
                    {
                        if (date.ValueKind != JsonValueKind.String) return null;
                        _ = ReadDate(date.GetString());
                    }
                }
            }
            return JsonSerializer.Deserialize<T>(buffer.GetBuffer().AsSpan(0, (int)buffer.Length), JsonOptions);
        }
        catch (JsonException) { return null; }
        catch (BadHttpRequestException) { return null; }
    }

    private static string CurrentUserId(HttpContext context) => ((AuthenticatedUser)context.Items["CurrentUser"]!).UserId;
    private static bool ValidId(string id) => id.Length is > 0 and <= 128 && id.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_');
    private static IResult Invalid(string message) => Error(400, "VALIDATION_ERROR", message);
    private static IResult Missing(string message) => Error(404, "NOT_FOUND", message);
    private static IResult Error(int status, string code, string message) => Results.Json(ApiResult<object>.Fail(code, message), statusCode: status);
    private static IResult Queued(NotificationTaskResult result) => Results.Json(ApiResult<NotificationTaskResult>.Ok(result, "发送任务已排队，可在邮件记录中查看结果。"), statusCode: 202);

    private static int PageNumber(string? text, int fallback, int maximum)
    {
        if (string.IsNullOrEmpty(text)) return fallback;
        return int.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out var result) && result >= 1 && result <= maximum
            ? result : throw new ArgumentException("分页参数无效。");
    }

    private static string? Filter(string? text, int maximum)
    {
        if (string.IsNullOrWhiteSpace(text)) return null;
        if (text.Length > maximum || text.Any(char.IsControl)) throw new ArgumentException("筛选参数无效。");
        return text.Trim();
    }

    private static DateTimeOffset? ReadDate(string? text)
    {
        if (string.IsNullOrEmpty(text)) return null;
        // 显式要求时区，避免部署主机的本地时区改变统计边界。
        var hasZone = text.EndsWith('Z') || text.EndsWith('z') ||
            (text.Length >= 6 && text[^3] == ':' && text[^6] is '+' or '-');
        if (!hasZone || text.Length > 40 || !DateTimeOffset.TryParse(text, CultureInfo.InvariantCulture, DateTimeStyles.None, out var parsed))
            throw new ArgumentException("时间必须使用带时区的 ISO 8601。");
        return parsed.ToUniversalTime();
    }
}
