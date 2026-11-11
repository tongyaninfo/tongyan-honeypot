using System.Text.Json;
using Honeypot.Api.Models;
using Honeypot.Api.Service;
using Honeypot.Shared.Models;
using Microsoft.AspNetCore.Http.Features;

namespace Honeypot.Api.Common;

public static class CredentialEvidenceEndpoints
{
    private const string ExportPath = "/api/v1/credential-evidence/export";
    private const int MaxExportItems = 8;
    private const int MaxExportRequestBytes = 4096;

    /// <summary>主应用鉴权中间件提前拒绝时记录证据访问失败，不读取请求正文或保存令牌。</summary>
    public static void AuditUnauthenticatedRead(HttpContext context)
    {
        const string prefix = "/api/v1/credential-evidence/";
        var path = context.Request.Path.Value ?? string.Empty;
        if (!path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) return;
        if (HttpMethods.IsPost(context.Request.Method) && path.TrimEnd('/').Equals(ExportPath, StringComparison.OrdinalIgnoreCase))
        {
            context.Response.Headers.CacheControl = "no-store";
            context.RequestServices.GetRequiredService<ICredentialEvidenceAccessService>().AuditExportDenied(null);
            return;
        }

        var artifact = path[prefix.Length..];
        if (artifact.Length == 0 || artifact.Contains('/') || artifact.Equals("audit", StringComparison.OrdinalIgnoreCase)) return;
        context.RequestServices.GetRequiredService<ICredentialEvidenceAccessService>().Read(artifact, null);
    }

    public static void MapCredentialEvidenceEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapPost(ExportPath, ExportAsync);

        endpoints.MapGet("/api/v1/credential-evidence", (HttpContext context, ICredentialEvidenceStore store) =>
        {
            if (context.Items["CurrentUser"] is not AuthenticatedUser)
                return Results.Json(ApiResult<object>.Fail("UNAUTHORIZED", "请先登录。"), statusCode: 401);
            // 列表只返回可关联的元数据，不返回密码或认证材料。
            var items = store.GetAll();
            context.Response.Headers.CacheControl = "no-store";
            return Results.Ok(ApiResult<object>.Ok(new { items, total = items.Count, page = 1, pageSize = items.Count }));
        });

        endpoints.MapGet("/api/v1/credential-evidence/audit", (HttpContext context, ICredentialEvidenceAccessService access) =>
        {
            var user = context.Items["CurrentUser"] as AuthenticatedUser;
            if (!UserAuthorization.IsAdministrator(user))
                return Results.Json(ApiResult<object>.Fail(user is null ? "UNAUTHORIZED" : "FORBIDDEN", "仅管理员可查询证据访问审计。"), statusCode: user is null ? 401 : 403);
            context.Response.Headers.CacheControl = "no-store";
            return Results.Ok(ApiResult<IReadOnlyCollection<CredentialEvidenceAudit>>.Ok(access.GetAuditTrail()));
        });

        endpoints.MapGet("/api/v1/credential-evidence/{credentialArtifactId}", (
            string credentialArtifactId, HttpContext context, ICredentialEvidenceAccessService access) =>
        {
            context.Response.Headers.CacheControl = "no-store";
            var result = access.Read(credentialArtifactId, context.Items["CurrentUser"] as AuthenticatedUser);
            return result.StatusCode == 200
                ? Results.Ok(ApiResult<CredentialEvidenceView>.Ok(result.Evidence!))
                : Results.Json(ApiResult<object>.Fail(result.Code, "证据不存在、已过期或没有读取权限。"), statusCode: result.StatusCode);
        });
    }

    private static async Task<IResult> ExportAsync(HttpContext context, ICredentialEvidenceAccessService access)
    {
        context.Response.Headers.CacheControl = "no-store";
        var user = context.Items["CurrentUser"] as AuthenticatedUser;
        // 鉴权在解析证据编号之前完成，拒绝时只记一次批次审计。
        if (!UserAuthorization.IsAdministrator(user))
        {
            access.AuditExportDenied(user);
            return Results.Json(ApiResult<object>.Fail(user is null ? "UNAUTHORIZED" : "FORBIDDEN", "仅管理员可导出证据原文。"), statusCode: user is null ? 401 : 403);
        }

        if (!context.Request.HasJsonContentType() || context.Request.ContentLength is > MaxExportRequestBytes)
            return InvalidExportRequest();

        // 限制未知长度请求的大小，兼容宿主已有的更小上限。
        if (context.Features.Get<IHttpMaxRequestBodySizeFeature>() is { IsReadOnly: false } sizeFeature)
            sizeFeature.MaxRequestBodySize = Math.Min(sizeFeature.MaxRequestBodySize ?? MaxExportRequestBytes, MaxExportRequestBytes);

        CredentialEvidenceExportRequest? request;
        try
        {
            request = await context.Request.ReadFromJsonAsync<CredentialEvidenceExportRequest>(context.RequestAborted);
        }
        catch (JsonException)
        {
            return InvalidExportRequest();
        }
        catch (BadHttpRequestException error) when (error.StatusCode == StatusCodes.Status413PayloadTooLarge)
        {
            return InvalidExportRequest();
        }

        if (request?.ArtifactIds is not { Length: > 0 and <= MaxExportItems } artifactIds ||
            artifactIds.Any(id => !IsEvidenceId(id)) ||
            artifactIds.Distinct(StringComparer.OrdinalIgnoreCase).Count() != artifactIds.Length)
            return InvalidExportRequest();

        var items = new List<CredentialEvidenceExportItem>(artifactIds.Length);
        foreach (var id in artifactIds)
        {
            context.RequestAborted.ThrowIfCancellationRequested();
            var result = access.ReadForExport(id!, user);
            items.Add(new(id!, result.Code, result.Evidence));
        }

        return Results.Ok(ApiResult<object>.Ok(new { items }));
    }

    private static bool IsEvidenceId(string? id) => id is { Length: 37 } &&
        id.StartsWith("cred-", StringComparison.OrdinalIgnoreCase) && Guid.TryParseExact(id.AsSpan(5), "N", out _);

    private static IResult InvalidExportRequest() => Results.BadRequest(
        ApiResult<object>.Fail("INVALID_EXPORT_REQUEST", $"请提供 1 到 {MaxExportItems} 个不同的证据编号。"));
}
