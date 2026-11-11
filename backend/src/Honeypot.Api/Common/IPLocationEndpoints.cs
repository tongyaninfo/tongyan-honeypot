using System.Text.Json;
using Honeypot.Api.Models;
using Honeypot.Api.Service;
using Honeypot.Shared.Models;

namespace Honeypot.Api.Common;

public static class IPLocationEndpoints
{
    private const int MaximumBodyBytes = 16 * 1024;

    public static void MapIPLocationEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/api/v1/settings/ip-location", (HttpContext context, IIPLocationSettingsStore store) =>
        {
            context.Response.Headers.CacheControl = "no-store";
            return Authorize(context, true) ?? Results.Ok(ApiResult<IPLocationSettings>.Ok(store.Current));
        });
        endpoints.MapPut("/api/v1/settings/ip-location", SaveAsync);
        endpoints.MapPost("/api/v1/ip-locations/resolve", ResolveAsync);
    }

    private static async Task<IResult> SaveAsync(HttpContext context, IIPLocationSettingsStore store)
    {
        context.Response.Headers.CacheControl = "no-store";
        if (Authorize(context, true) is { } denied) return denied;
        var settings = await ReadLimitedAsync<IPLocationSettings>(context);
        if (settings is null || !IPLocationSettingsValidation.TryNormalize(settings, out var normalized))
            return Invalid("请填写 HTTP/HTTPS、有效主机和端口、支持的数据库，以及 0.1–30 秒超时。");
        try { await store.SaveAsync(normalized, context.RequestAborted); }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            return Results.Json(ApiResult<object>.Fail("CONFIG_SAVE_FAILED", "配置保存失败，请检查数据目录权限。"), statusCode: 500);
        }
        return Results.Ok(ApiResult<IPLocationSettings>.Ok(store.Current));
    }

    private static async Task<IResult> ResolveAsync(HttpContext context, IIPLocationResolver resolver)
    {
        context.Response.Headers.CacheControl = "no-store";
        if (Authorize(context, false) is { } denied) return denied;
        var request = await ReadLimitedAsync<IPLocationBatchRequest>(context);
        if (request?.Ips is not { Length: > 0 and <= 100 } ips || ips.Any(ip => string.IsNullOrWhiteSpace(ip) || ip.Length > 80))
            return Invalid("每批请提供 1–100 个 IP 地址，每项不超过 80 字符。");
        return Results.Ok(ApiResult<IPLocationBatchResult>.Ok(resolver.Resolve(ips.Select(ip => ip!.Trim()).ToArray())));
    }

    private static IResult? Authorize(HttpContext context, bool administrator)
    {
        if (context.Items["CurrentUser"] is not AuthenticatedUser user)
            return Results.Json(ApiResult<object>.Fail("UNAUTHORIZED", "请先登录。"), statusCode: 401);
        return administrator && !UserAuthorization.IsAdministrator(user)
            ? Results.Json(ApiResult<object>.Fail("FORBIDDEN", "仅管理员可管理 IP 数据库配置。"), statusCode: 403) : null;
    }

    private static async Task<T?> ReadLimitedAsync<T>(HttpContext context) where T : class
    {
        if (!context.Request.HasJsonContentType() || context.Request.ContentLength > MaximumBodyBytes) return null;
        try
        {
            // 手动限量读取同时覆盖 chunked 请求，避免 JSON 绑定前分配无界内存。
            using var body = new MemoryStream();
            var buffer = new byte[4096];
            while (true)
            {
                var count = await context.Request.Body.ReadAsync(buffer, context.RequestAborted);
                if (count == 0) break;
                if (body.Length + count > MaximumBodyBytes) return null;
                body.Write(buffer, 0, count);
            }
            return JsonSerializer.Deserialize<T>(body.GetBuffer().AsSpan(0, (int)body.Length), new JsonSerializerOptions(JsonSerializerDefaults.Web) { MaxDepth = 8 });
        }
        catch (JsonException) { return null; }
        catch (BadHttpRequestException) { return null; }
    }

    private static IResult Invalid(string message) => Results.BadRequest(ApiResult<object>.Fail("VALIDATION_ERROR", message));
}
