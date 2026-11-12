using System.Data.Common;
using System.Globalization;
using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;
using Honeypot.Api.Models;
using Honeypot.Api.Service;
using Honeypot.Api.Service.impl;
using Honeypot.Shared.Models;
using Microsoft.EntityFrameworkCore;

namespace Honeypot.Api.Common;

public static class McpManagementEndpoints
{
    private const int MaximumBodyBytes = 16 * 1024;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        MaxDepth = 8,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };

    public static void MapMcpManagementEndpoints(this IEndpointRouteBuilder endpoints)
    {
        var group = endpoints.MapGroup("/api/v1/mcp").AddEndpointFilter(async (invocation, next) =>
        {
            var context = invocation.HttpContext;
            context.Response.Headers.CacheControl = "no-store";
            var user = User(context);
            if (user is null) return Error(401, "UNAUTHORIZED", "请先登录。");
            if (!UserAuthorization.IsAdministrator(user)) return Error(403, "FORBIDDEN", "仅管理员可管理 MCP 服务。");
            try
            {
                return await next(invocation);
            }
            catch (Exception error) when (error is DbException or DbUpdateException or JsonException)
            {
                Log(context.RequestServices.GetRequiredService<ISyslogPublisher>(), "MCP_STORAGE_UNAVAILABLE", user.UserId);
                return Error(503, "MCP_STORAGE_UNAVAILABLE", "MCP 存储暂不可用，请检查运行状态。");
            }
        });

        group.MapGet("/settings", async (HttpContext context, SqliteMcpStore store) =>
            Ok(await store.GetSettingsAsync(context.RequestAborted)));
        group.MapPut("/settings", UpdateSettingsAsync);
        group.MapGet("/permissions", (IServiceInstanceStore instances) => Ok(GetPermissions(instances)));
        group.MapGet("/keys", GetKeysAsync);
        group.MapPost("/keys", CreateKeyAsync);
        group.MapPost("/keys/{id}/revoke", RevokeKeyAsync);
        group.MapDelete("/keys/{id}", DeleteKeyAsync);
        group.MapGet("/audits", GetAuditsAsync);
        group.MapGet("/audits/{id}", GetAuditAsync);
    }

    private static async Task<IResult> UpdateSettingsAsync(HttpContext context, SqliteMcpStore store, ISyslogPublisher logs)
    {
        var request = await ReadAsync<McpUpdateSettingsRequest>(context);
        if (request is null || (request.Enabled is null && request.AuditRetentionDays is null)
            || request.AuditRetentionDays is < 1 or > 365)
            return Error(400, "INVALID_MCP_SETTINGS", "请提供服务状态或 1–365 天的审计留存。");

        var actor = User(context)!.UserId;
        var settings = await store.UpdateSettingsAsync(request, actor, context.RequestAborted);
        Log(logs, "MCP_SETTINGS_UPDATED", actor);
        return Ok(settings);
    }

    private static McpPermissions GetPermissions(IServiceInstanceStore instances) => new(
        McpToolCatalog.All.GroupBy(tool => tool.Group, StringComparer.Ordinal).Select(group => new McpPermissionGroup(
            group.Key, group.First().GroupLabel, group.Select(tool => new McpPermission(tool.Name, tool.DisplayName,
                tool.Description, tool.IsWrite ? McpAccess.ReadWrite : McpAccess.ReadOnly, tool.RequiresInstanceScope)).ToArray())).ToArray(),
        instances.GetAll().OrderBy(instance => instance.DisplayName, StringComparer.OrdinalIgnoreCase)
            .ThenBy(instance => instance.InstanceId, StringComparer.Ordinal)
            .Select(instance => new McpGrantableInstance(instance.InstanceId, instance.DisplayName, instance.AdapterKey)).ToArray());

    private static async Task<IResult> GetKeysAsync(HttpContext context, SqliteMcpStore store)
    {
        if (!TryPage(context.Request.Query, out var page, out var pageSize)) return InvalidQuery();
        return Ok(await store.GetKeysAsync(page, pageSize, context.RequestAborted));
    }

    private static async Task<IResult> CreateKeyAsync(HttpContext context, SqliteMcpStore store,
        IServiceInstanceStore instances, TimeProvider clock, ISyslogPublisher logs)
    {
        var request = await ReadAsync<McpCreateKeyRequest>(context);
        var name = request?.Name?.Trim();
        if (request is null || string.IsNullOrWhiteSpace(name) || name.Length > 100 || name.Any(char.IsControl)
            || request.Access is not (McpAccess.ReadOnly or McpAccess.ReadWrite))
            return Error(400, "INVALID_MCP_KEY", "请填写 1–100 个字符的名称并选择权限模式。");
        if (!TryTimestamp(request.ExpiresAtUtc, out var expires) || expires <= clock.GetUtcNow())
            return Error(400, "INVALID_MCP_KEY_EXPIRY", "有效期须为包含时区的未来时间，留空表示永久。");

        if (!TryPermissions(request, out var tools))
            return Error(400, "INVALID_MCP_PERMISSIONS", "请勾选当前模式允许的权限，至少选择一项。");
        if (!TryGrants(request.InstanceIds ?? [], tools, instances, out var grants))
            return Error(400, "INVALID_MCP_INSTANCE_SCOPE", "请选择要授权的已保存实例。仅实例写工具需要实例范围。");

        var actor = User(context)!.UserId;
        var created = await store.CreateKeyAsync(name, request.Access, tools.Select(tool => tool.Name).ToArray(),
            grants, expires, actor, context.RequestAborted);
        Log(logs, "MCP_KEY_CREATED", actor, created.Key.Id);
        return Results.Json(ApiResult<McpCreatedKey>.Ok(created), statusCode: 201);
    }

    private static bool TryPermissions(McpCreateKeyRequest request, out List<McpToolDescriptor> tools)
    {
        tools = [];
        if (request.PermissionIds is not { Length: > 0 } selected || selected.Length > McpToolCatalog.All.Count) return false;
        foreach (var id in selected.Distinct(StringComparer.Ordinal))
        {
            if (id is null || !McpToolCatalog.TryGet(id, out var tool) || (tool.IsWrite && request.Access == McpAccess.ReadOnly))
                return false;
            tools.Add(tool);
        }
        return true;
    }

    private static bool TryGrants(string[] selected, List<McpToolDescriptor> tools,
        IServiceInstanceStore instances, out McpInstanceGrant[] grants)
    {
        grants = [];
        if (!tools.Any(tool => tool.RequiresInstanceScope)) return selected.Length == 0;
        if (selected.Length is < 1 or > 100) return false;
        var result = new Dictionary<string, McpInstanceGrant>(StringComparer.OrdinalIgnoreCase);
        foreach (var id in selected)
        {
            if (string.IsNullOrWhiteSpace(id) || id.Length > 128 || instances.Get(id) is not { } instance) return false;
            result.TryAdd(instance.InstanceId, new(instance.InstanceId, McpInstanceScope.BindingFingerprint(instance)));
        }
        grants = result.Values.ToArray();
        return true;
    }

    private static async Task<IResult> RevokeKeyAsync(string id, HttpContext context, SqliteMcpStore store, ISyslogPublisher logs)
    {
        if (!await store.RevokeKeyAsync(id, context.RequestAborted))
            return Error(404, "MCP_KEY_NOT_FOUND", "API Key 不存在。");
        Log(logs, "MCP_KEY_REVOKED", User(context)!.UserId, id);
        return Ok(new { id });
    }

    private static async Task<IResult> DeleteKeyAsync(string id, HttpContext context, SqliteMcpStore store, ISyslogPublisher logs)
    {
        var result = await store.DeleteKeyAsync(id, context.RequestAborted);
        if (result == "MCP_KEY_NOT_FOUND") return Error(404, result, "API Key 不存在。");
        if (result != "OK") return Error(409, result, "请先吊销 API Key，再删除。");
        Log(logs, "MCP_KEY_DELETED", User(context)!.UserId, id);
        return Ok(new { id });
    }

    private static async Task<IResult> GetAuditsAsync(HttpContext context, SqliteMcpStore store)
    {
        var query = context.Request.Query;
        if (!TryPage(query, out var page, out var pageSize) ||
            !TryFilter(query, "keyId", 128, out var keyId) ||
            !TryFilter(query, "tool", 128, out var tool) ||
            !TryFilter(query, "sourceIp", 64, out var ip) ||
            !TryFilter(query, "result", 24, out var result) ||
            !TryFilter(query, "fromUtc", 40, out var fromText) || !TryTimestamp(fromText, out var from) ||
            !TryFilter(query, "toUtc", 40, out var toText) || !TryTimestamp(toText, out var to) ||
            from >= to || (result is not null && !McpAuditResult.IsKnown(result)))
            return InvalidQuery();

        if (ip is not null)
        {
            if (!IPAddress.TryParse(ip, out var address)) return InvalidQuery();
            ip = McpInstanceScope.Normalize(address).ToString();
        }
        return Ok(await store.GetAuditsAsync(new(page, pageSize, keyId, tool, ip, result, from, to), context.RequestAborted));
    }

    private static async Task<IResult> GetAuditAsync(string id, HttpContext context, SqliteMcpStore store)
    {
        var audit = await store.GetAuditAsync(id, context.RequestAborted);
        return audit is null ? Error(404, "MCP_AUDIT_NOT_FOUND", "调用记录不存在或已过期。") : Ok(audit);
    }

    private static bool TryPage(IQueryCollection query, out int page, out int size)
    {
        var pageOk = TryQueryInt(query, "page", 1, 1_000_000, out page);
        return TryQueryInt(query, "pageSize", 20, 100, out size) && pageOk;
    }

    private static bool TryQueryInt(IQueryCollection query, string name, int defaultValue, int max, out int value)
    {
        value = defaultValue;
        return !query.TryGetValue(name, out var raw) || (raw.Count == 1 &&
            int.TryParse(raw[0], NumberStyles.None, CultureInfo.InvariantCulture, out value) && value >= 1 && value <= max);
    }

    private static bool TryFilter(IQueryCollection query, string name, int maximum, out string? value)
    {
        value = null;
        if (!query.TryGetValue(name, out var raw)) return true;
        if (raw.Count != 1 || raw[0] is not { } text || text.Length > maximum || text.Any(char.IsControl)) return false;
        value = string.IsNullOrWhiteSpace(text) ? null : text.Trim();
        return true;
    }

    private static bool TryTimestamp(string? text, out DateTimeOffset? timestamp)
    {
        timestamp = null;
        if (string.IsNullOrWhiteSpace(text)) return true;
        if (text.Length is < 20 or > 40 || text[10] != 'T' || !(text.EndsWith('Z') || (text[^6] is '+' or '-' && text[^3] == ':'))
            || !DateTimeOffset.TryParse(text, CultureInfo.InvariantCulture, DateTimeStyles.None, out var value)) return false;
        timestamp = value.ToUniversalTime();
        return true;
    }

    private static async Task<T?> ReadAsync<T>(HttpContext context) where T : class
    {
        var request = context.Request;
        if (!request.HasJsonContentType() || request.ContentLength > MaximumBodyBytes) return null;
        var data = new byte[MaximumBodyBytes + 1];
        try
        {
            var count = await request.Body.ReadAtLeastAsync(data, data.Length, false, context.RequestAborted);
            return count <= MaximumBodyBytes ? JsonSerializer.Deserialize<T>(data.AsSpan(0, count), JsonOptions) : null;
        }
        catch (Exception error) when (error is JsonException or BadHttpRequestException) { return null; }
    }

    private static void Log(ISyslogPublisher logs, string code, string actor, string? keyId = null) =>
        SyslogInteractionProjection.PublishSafely(logs, "honeypot-mcp", code,
            code == "MCP_STORAGE_UNAVAILABLE" ? SyslogSeverity.Error : SyslogSeverity.Notice,
            new Dictionary<string, object?> { ["actorUserId"] = actor, ["subjectId"] = keyId });

    private static AuthenticatedUser? User(HttpContext context) => context.Items["CurrentUser"] as AuthenticatedUser;
    private static IResult InvalidQuery() => Error(400, "INVALID_MCP_QUERY", "请检查分页、筛选项和起止时间。");
    private static IResult Ok<T>(T value) => Results.Ok(ApiResult<T>.Ok(value));
    private static IResult Error(int status, string code, string message) =>
        Results.Json(ApiResult<object>.Fail(code, message), statusCode: status);
}
