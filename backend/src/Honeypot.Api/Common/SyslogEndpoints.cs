using System.Collections.Concurrent;
using System.Text.Json;
using System.Text.Json.Serialization;
using Honeypot.Api.Models;
using Honeypot.Api.Service;
using Honeypot.Shared.Models;

namespace Honeypot.Api.Common;

/// <summary>管理操作使用当前真实会话；浏览器日志只接受固定诊断码，不能指定目标或严重级别。</summary>
public static class SyslogEndpoints
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    { MaxDepth = 8, UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow };
    private static readonly ConcurrentDictionary<string, RateWindow> Rates = new(StringComparer.Ordinal);
    private static readonly SemaphoreSlim TestGate = new(1, 1);
    private static readonly HashSet<string> Routes = ["overview", "services", "events", "threats", "credentials", "reports", "system", "unknown"];
    private static readonly IReadOnlyDictionary<string, SyslogSeverity> DiagnosticLevels = new Dictionary<string, SyslogSeverity>(StringComparer.Ordinal)
    {
        ["UI_UNHANDLED_ERROR"] = SyslogSeverity.Error,
        ["UI_EXPORT_FAILED"] = SyslogSeverity.Error,
        ["UI_REQUEST_FAILED"] = SyslogSeverity.Warning,
        ["UI_REALTIME_INTERRUPTED"] = SyslogSeverity.Warning,
        ["UI_REALTIME_RECOVERED"] = SyslogSeverity.Notice,
        ["UI_NETWORK_RECOVERED"] = SyslogSeverity.Notice,
    };

    public static void MapSyslogEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/api/v1/settings/syslog", (HttpContext context, ISyslogSettingsStore settings) =>
        {
            context.Response.Headers.CacheControl = "no-store";
            return Authorize(context, true) ?? Results.Ok(ApiResult<SyslogSettingsSnapshot>.Ok(settings.Current));
        });
        endpoints.MapPut("/api/v1/settings/syslog", SaveAsync);
        endpoints.MapGet("/api/v1/syslog/status", (HttpContext context, ISyslogDeliveryService delivery) =>
        {
            context.Response.Headers.CacheControl = "no-store";
            return Authorize(context, true) ?? Results.Ok(ApiResult<SyslogDeliveryStatus>.Ok(delivery.GetStatus()));
        });
        endpoints.MapPost("/api/v1/syslog/test", TestAsync);
        endpoints.MapPost("/api/v1/telemetry/frontend-logs", RecordFrontendAsync);
    }

    private static async Task<IResult> SaveAsync(HttpContext context, ISyslogSettingsStore settings, ISyslogPublisher publisher, ILoggerFactory loggerFactory)
    {
        context.Response.Headers.CacheControl = "no-store";
        if (Authorize(context, true) is { } denied) return denied;
        var request = await ReadAsync<UpdateSyslogSettingsRequest>(context);
        if (request is null || request.ExpectedRevision < 0 || !SyslogSettingsValidation.TryNormalize(request.Settings, out var normalized))
            return Error(400, "VALIDATION_ERROR", "请检查目标地址、协议、端口和缓存限制，最多配置 3 个目标。");
        var previous = settings.Current;
        var localAudit = loggerFactory.CreateLogger("Honeypot.Syslog.LocalAudit");
        try
        {
            var saved = await settings.SaveAsync(normalized, request.ExpectedRevision, context.RequestAborted);
            // 独立本地审计不进入 Syslog Provider，关闭外发也能留下修改记录。
            localAudit.LogInformation("Syslog settings saved. ActorUserId={ActorUserId} Revision={Revision} Enabled={Enabled} TlsBypassCount={TlsBypassCount}",
                User(context)?.UserId, saved.Revision, saved.Settings.Enabled, saved.Settings.Targets.Count(target => target.IgnoreSslErrors));
            var fields = new Dictionary<string, object?> { ["actorUserId"] = User(context)?.UserId, ["revision"] = saved.Revision, ["enabled"] = saved.Settings.Enabled, ["targetCount"] = saved.Settings.Targets.Length };
            publisher.Publish("honeypot-settings", "SYSLOG_SETTINGS_SAVED", SyslogSeverity.Notice, fields);
            if (normalized.Targets.Any(target => target.IgnoreSslErrors && !previous.Settings.Targets.Any(old => old.Id == target.Id && old.Protocol == SyslogProtocol.Tls && old.IgnoreSslErrors)))
                publisher.Publish("honeypot-settings", "SYSLOG_TLS_VALIDATION_DISABLED", SyslogSeverity.Warning, fields);
            return Results.Ok(ApiResult<SyslogSettingsSnapshot>.Ok(saved));
        }
        catch (SyslogSettingsConflictException) { return Error(409, "CONFIG_VERSION_CONFLICT", "配置已被其他操作修改，请重新读取后保存。"); }
        catch (SyslogSettingsUnavailableException) { return Error(503, "SYSLOG_CONFIGURATION_UNAVAILABLE", "原配置不可读取，已停止外发；请管理员修复原配置后重启，不会自动覆盖。"); }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            localAudit.LogError("Syslog settings save failed. ActorUserId={ActorUserId} ErrorCode={ErrorCode}", User(context)?.UserId, "CONFIG_SAVE_FAILED");
            publisher.Publish("honeypot-settings", "SYSLOG_SETTINGS_SAVE_FAILED", SyslogSeverity.Error,
                new Dictionary<string, object?> { ["actorUserId"] = User(context)?.UserId, ["errorCode"] = "CONFIG_SAVE_FAILED" });
            return Error(500, "CONFIG_SAVE_FAILED", "配置保存失败，请检查数据目录权限与空间。");
        }
    }

    private static async Task<IResult> TestAsync(HttpContext context, ISyslogSettingsStore settings, ISyslogDeliveryService delivery)
    {
        context.Response.Headers.CacheControl = "no-store";
        if (Authorize(context, true) is { } denied) return denied;
        var request = await ReadAsync<SyslogTestRequest>(context);
        if (request is null || !settings.Current.Settings.Targets.Any(target => target.Id == request.TargetId))
            return Error(400, "VALIDATION_ERROR", "请选择已经保存的 Syslog 目标。");
        if (request.Message is { } message && (message.Length > SyslogTestRequest.MaximumMessageLength || message.Any(char.IsControl)))
            return Error(400, "VALIDATION_ERROR", "测试消息最多 256 个字符，请填写单行文本。");
        if (!Allow(User(context)!.UserId, "test", 2) || !await TestGate.WaitAsync(0, context.RequestAborted))
            return Error(429, "RATE_LIMITED", "测试繁忙或过于频繁，每分钟最多测试 2 次。");
        try
        {
            var result = await delivery.TestAsync(request.TargetId, request.Message?.Trim(), context.RequestAborted);
            return Results.Ok(ApiResult<SyslogTestResult>.Ok(result));
        }
        finally { TestGate.Release(); }
    }

    private static async Task<IResult> RecordFrontendAsync(HttpContext context, ISyslogPublisher publisher)
    {
        context.Response.Headers.CacheControl = "no-store";
        if (Authorize(context, false) is { } denied) return denied;
        if (!Allow(User(context)!.UserId, "frontend", 30)) return Error(429, "RATE_LIMITED", "诊断上报过于频繁。");
        var request = await ReadAsync<FrontendDiagnosticRequest>(context);
        if (request is null || !DiagnosticLevels.TryGetValue(request.EventCode ?? "", out var severity) ||
            !Routes.Contains(request.RouteKey ?? "") || request.Count is < 1 or > 20 || request.HttpStatus is not null and not (>= 400 and <= 599))
            return Error(400, "VALIDATION_ERROR", "前端诊断格式无效。");
        publisher.Publish("honeypot-webui", request.EventCode!, severity, new Dictionary<string, object?>
        { ["actorUserId"] = User(context)?.UserId, ["routeKey"] = request.RouteKey, ["statusCode"] = request.HttpStatus, ["count"] = request.Count });
        return Results.Ok(ApiResult<object>.Ok(new { accepted = true }));
    }

    private static AuthenticatedUser? User(HttpContext context) => context.Items["CurrentUser"] as AuthenticatedUser;
    private static IResult? Authorize(HttpContext context, bool administrator) => User(context) is not { } user
        ? Error(401, "UNAUTHORIZED", "请先登录。")
        : administrator && !UserAuthorization.IsAdministrator(user) ? Error(403, "FORBIDDEN", "仅管理员可管理 Syslog。") : null;

    private static async Task<T?> ReadAsync<T>(HttpContext context) where T : class
    {
        if (!context.Request.HasJsonContentType() || context.Request.ContentLength > 16384) return null;
        try
        {
            using var body = new MemoryStream();
            var buffer = new byte[4096];
            while (true)
            {
                var count = await context.Request.Body.ReadAsync(buffer, context.RequestAborted);
                if (count == 0) break;
                if (body.Length + count > 16384) return null;
                body.Write(buffer, 0, count);
            }
            return JsonSerializer.Deserialize<T>(body.GetBuffer().AsSpan(0, (int)body.Length), JsonOptions);
        }
        catch (JsonException) { return null; }
        catch (BadHttpRequestException) { return null; }
    }

    private static bool Allow(string userId, string scope, int maximum)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 60;
        // 限制会话键数量，避免上报接口自身形成无界存储。
        if (Rates.Count >= 1024)
        {
            foreach (var pair in Rates.Where(pair => pair.Value.Minute < now - 1)) Rates.TryRemove(pair.Key, out _);
            if (Rates.Count >= 1024 && !Rates.ContainsKey(scope + ":" + userId)) return false;
        }
        var window = Rates.AddOrUpdate(scope + ":" + userId, _ => new(now, 1), (_, old) => old.Minute == now ? old with { Count = old.Count + 1 } : new(now, 1));
        return window.Count <= maximum;
    }
    private sealed record RateWindow(long Minute, int Count);
    private static IResult Error(int status, string code, string message) => Results.Json(ApiResult<object>.Fail(code, message), statusCode: status);
}
