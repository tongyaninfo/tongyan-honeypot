using Honeypot.Api.Models;
using Honeypot.Api.Service;
using Honeypot.Shared.Models;

namespace Honeypot.Api.Common;

public static class PasswordBookEndpoints
{
    internal const string Path = "/api/v1/password-book";
    private const int MaxKeywordLength = 128;

    public static void MapPasswordBookEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet(Path, (HttpContext context, ICredentialEvidenceStore store, int? page, int? pageSize, string? keyword) =>
        {
            context.Response.Headers.CacheControl = "no-store";
            var user = context.Items["CurrentUser"] as AuthenticatedUser;
            if (!UserAuthorization.IsAdministrator(user))
                return Results.Json(ApiResult<object>.Fail(user is null ? "UNAUTHORIZED" : "FORBIDDEN",
                    "仅管理员可查看密码簿。"), statusCode: user is null ? 401 : 403);

            var filter = keyword?.Trim();
            if (filter is { Length: > MaxKeywordLength })
                return Results.BadRequest(ApiResult<object>.Fail("INVALID_PASSWORD_BOOK_KEYWORD", $"搜索关键词最多 {MaxKeywordLength} 个字符。"));

            return Results.Ok(ApiResult<object>.Ok(store.GetPasswordBookPage(page, pageSize, filter)));
        });
    }
}
