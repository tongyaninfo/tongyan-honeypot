using System.Data.Common;
using System.Globalization;
using Honeypot.Api.Models;
using Honeypot.Api.Service.impl;
using Honeypot.Shared.Models;
using Microsoft.EntityFrameworkCore;

namespace Honeypot.Api.Common;

public static class ManagementOperationAuditEndpoints
{
    public static void MapManagementOperationAuditEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/api/v1/management/audits", ReadAsync);
    }

    private static async Task<IResult> ReadAsync(HttpContext context, ManagementOperationAuditStore store)
    {
        context.Response.Headers.CacheControl = "no-store";
        if (context.Items["CurrentUser"] is not AuthenticatedUser user)
            return Results.Json(ApiResult<object>.Fail("UNAUTHORIZED", "请先登录。"), statusCode: 401);
        if (!UserAuthorization.IsAdministrator(user))
            return Results.Json(ApiResult<object>.Fail("FORBIDDEN", "仅管理员可查看管理操作审计。"), statusCode: 403);

        var query = context.Request.Query;
        if (!TryPageValue("page", 1, int.MaxValue, out var number) ||
            !TryPageValue("pageSize", 20, 100, out var size))
            return Results.BadRequest(ApiResult<object>.Fail("VALIDATION_ERROR", "页码必须大于 0，每页最多 100 条。"));
        try
        {
            var (items, total) = await store.GetPageAsync(number, size, context.RequestAborted);
            return Results.Ok(ApiResult<object>.Ok(new { items, total, page = number, pageSize = size }));
        }
        catch (Exception error) when (error is DbException or DbUpdateException)
        {
            return Results.Json(ApiResult<object>.Fail("MANAGEMENT_AUDIT_UNAVAILABLE", "管理操作审计暂不可用。"), statusCode: 503);
        }

        bool TryPageValue(string key, int fallback, int maximum, out int value)
        {
            value = fallback;
            return !query.TryGetValue(key, out var raw) ||
                (raw.Count == 1 && int.TryParse(raw[0], NumberStyles.None, CultureInfo.InvariantCulture, out value) &&
                    value >= 1 && value <= maximum);
        }
    }
}
