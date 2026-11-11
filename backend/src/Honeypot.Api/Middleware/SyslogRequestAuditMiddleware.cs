using System.Diagnostics;
using Honeypot.Api.Models;
using Honeypot.Api.Service;
using Honeypot.Shared.Models;

namespace Honeypot.Api.Middleware;

public sealed class SyslogRequestAuditMiddleware(RequestDelegate next)
{
    public async Task InvokeAsync(HttpContext context, ISyslogPublisher logs)
    {
        if (!context.Request.Path.StartsWithSegments("/api") && !context.Request.Path.StartsWithSegments("/health") &&
            !context.Request.Path.StartsWithSegments("/hubs/honeypot"))
        {
            await next(context);
            return;
        }

        var start = Stopwatch.GetTimestamp();
        try { await next(context); }
        catch (OperationCanceledException) when (context.RequestAborted.IsCancellationRequested) { throw; }
        catch (Exception error)
        {
            // 路由模板和异常类型可用于排障。异常正文、查询参数及认证内容留在业务边界内。
            Write(context, logs, start, 500, error.GetType().Name);
            throw;
        }
        Write(context, logs, start, context.Response.StatusCode, null);
    }

    private static void Write(HttpContext context, ISyslogPublisher logs, long start, int status, string? exceptionType)
    {
        var route = (context.GetEndpoint() as RouteEndpoint)?.RoutePattern.RawText ?? "unmatched";
        var method = context.Request.Method;
        var userId = (context.Items["CurrentUser"] as AuthenticatedUser)?.UserId;
        var app = "honeypot-api";
        var code = "HTTP_REQUEST_COMPLETED";
        var severity = status switch
        {
            >= 500 => SyslogSeverity.Error,
            401 or 403 => SyslogSeverity.Warning,
            >= 400 => SyslogSeverity.Informational,
            _ => HttpMethods.IsGet(method) ? SyslogSeverity.Debug : SyslogSeverity.Informational
        };
        switch (route, method)
        {
            case ("/api/v1/auth/login", "POST"):
                app = "honeypot-identity";
                code = status < 400 ? "ADMIN_LOGIN_SUCCEEDED" : "ADMIN_LOGIN_REJECTED";
                if (status < 400) severity = SyslogSeverity.Notice;
                break;
            case ("/api/v1/auth/logout", "POST"):
                app = "honeypot-identity";
                code = "ADMIN_LOGOUT";
                if (status < 400 && userId is not null) severity = SyslogSeverity.Notice;
                break;
            case ("/api/v1/setup/initialize", "POST"):
                app = "honeypot-identity";
                code = "ADMIN_INITIALIZATION";
                if (status < 400) severity = SyslogSeverity.Notice;
                break;
            case ("/api/v1/settings/notifications" or "/api/v1/settings/ip-location", "PUT"):
                app = "honeypot-settings";
                code = "SETTINGS_UPDATE";
                if (status < 400) severity = SyslogSeverity.Notice;
                break;
            case ("/api/v1/service-instances" or "/api/v1/service-instances/{instanceId}/apply"
                or "/api/v1/service-instances/{instanceId}/start" or "/api/v1/service-instances/{instanceId}/stop"
                or "/api/v1/service-instances/{instanceId}/restart-policy", "POST"):
                app = "honeypot-runtime";
                code = "SERVICE_INSTANCE_OPERATION";
                if (status < 400) severity = SyslogSeverity.Notice;
                if (status == 409) severity = SyslogSeverity.Error;
                break;
        }
        if (route.StartsWith("/hubs/honeypot", StringComparison.Ordinal))
            app = "honeypot-realtime";
        logs.Publish(app, code, severity, new Dictionary<string, object?>
        {
            ["route"] = route, ["method"] = method, ["statusCode"] = status, ["traceId"] = context.TraceIdentifier,
            ["elapsedMs"] = (long)Stopwatch.GetElapsedTime(start).TotalMilliseconds, ["actorUserId"] = userId,
            ["exceptionType"] = exceptionType,
        });
    }
}
