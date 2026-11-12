using System.Net;
using Honeypot.Api.Common;
using Honeypot.Api.Models;
using Honeypot.Api.Options;
using Honeypot.Api.Service;
using Microsoft.Extensions.Options;

namespace Honeypot.Api.Middleware;

internal sealed class McpTransportMiddleware(
    RequestDelegate next,
    IOptions<McpTransportOptions> configured,
    McpTrafficLimiter limiter,
    ILogger<McpTransportMiddleware> logger)
{
    private readonly McpTransportOptions options = configured.Value;
    private readonly System.Net.IPNetwork[] insecureNetworks = configured.Value.InsecureHttpNetworks
        .Select(network => System.Net.IPNetwork.TryParse(network, out var parsed) ? parsed : (System.Net.IPNetwork?)null)
        .OfType<System.Net.IPNetwork>().ToArray();

    public async Task InvokeAsync(HttpContext http, IMcpStore store, McpAuditHealth auditHealth, IUserIdentityService identity)
    {
        var request = http.Request;
        var response = http.Response;
        var ip = http.Connection.RemoteIpAddress;
        if (ip?.IsIPv4MappedToIPv6 == true) ip = ip.MapToIPv4();
        var candidate = BearerToken(request);
        var audit = new McpHttpAuditState(http, ip?.ToString(), candidate);
        http.Items[typeof(McpHttpAuditState)] = audit;
        response.Headers.CacheControl = "no-store, private";

        var originalResponse = response.Body;
        using var captured = new McpResponseCapture(originalResponse);
        response.Body = captured;
        var originalRequest = request.Body;
        var originalAbort = http.RequestAborted;
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(originalAbort);
        deadline.CancelAfter(TimeSpan.FromSeconds(20));
        http.RequestAborted = deadline.Token;
        using var sourceLease = limiter.EnterSource(ip?.ToString() ?? "unknown");
        var admitted = false;

        try
        {
            if (sourceLease is null)
            {
                audit.RequestBodyOmittedReason = "RATE_LIMITED";
                response.Headers.RetryAfter = "60";
                await Reject(http, audit, 429, McpAuditResult.RateLimited, "SOURCE_LIMIT", "请求过多，请稍后重试。");
                return;
            }

            audit.CaptureRequestHeaders();
            if (!IsAcceptedHost(request.Host, ip) || !IsAcceptedOrigin(request))
            {
                await Reject(http, audit, 403, McpAuditResult.Denied, "UNTRUSTED_ORIGIN", "接入主机或浏览器来源不在允许范围内。");
                return;
            }
            if (!request.IsHttps && (ip is null || (!IPAddress.IsLoopback(ip) && !insecureNetworks.Any(network => network.Contains(ip)))))
            {
                await Reject(http, audit, 403, McpAuditResult.Denied, "HTTPS_REQUIRED", "此来源需要使用 HTTPS 接入。");
                return;
            }
            if (!string.Equals(request.Path.Value?.TrimEnd('/'), "/mcp", StringComparison.OrdinalIgnoreCase))
            {
                await Reject(http, audit, 404, McpAuditResult.ProtocolError, "ENDPOINT_NOT_FOUND", "MCP 路径不存在。");
                return;
            }
            if (request.QueryString.HasValue)
            {
                await Reject(http, audit, 400, McpAuditResult.ProtocolError, "QUERY_NOT_SUPPORTED", "MCP 端点不接收 URL 参数。");
                return;
            }
            if (!identity.IsInitialized || !(await store.GetSettingsAsync(deadline.Token)).Enabled)
            {
                await Reject(http, audit, 503, McpAuditResult.Unavailable, "MCP_DISABLED", "MCP 服务未启动。");
                return;
            }

            var auth = candidate is { Length: > 0 and <= 128 } ? await store.AuthenticateAsync(candidate, deadline.Token) : null;
            audit.Key = auth?.Key;
            if (auth is not { Code: "OK", Key: not null })
            {
                response.Headers.WWWAuthenticate = "Bearer realm=\"Honeypot MCP\"";
                // 向调用方返回统一的鉴权失败，细分原因仅供管理员审计。
                await Reject(http, audit, 401, McpAuditResult.Denied, "INVALID_API_KEY", "需要有效的 MCP API Key。");
                audit.ErrorCode = auth?.Code ?? "MISSING_API_KEY";
                return;
            }
            using var keyLease = limiter.EnterKey(auth.Key.Id);
            if (keyLease is null)
            {
                response.Headers.RetryAfter = "60";
                await Reject(http, audit, 429, McpAuditResult.RateLimited, "KEY_LIMIT", "该 API Key 的调用已达限额。");
                return;
            }
            admitted = true;

            if (!HttpMethods.IsPost(request.Method))
            {
                response.Headers.Allow = "POST";
                await Reject(http, audit, 405, McpAuditResult.ProtocolError, "METHOD_NOT_ALLOWED", "当前 MCP 服务只处理 POST 请求。");
                return;
            }
            if (request.ContentLength > McpAuditPayload.MaxRequestBytes)
            {
                audit.RequestBodyOmittedReason = "REQUEST_LIMIT";
                await Reject(http, audit, 413, McpAuditResult.ProtocolError, "REQUEST_TOO_LARGE", "MCP 请求不得超过 32 KiB。");
                return;
            }
            var bytes = new byte[McpAuditPayload.MaxRequestBytes + 1];
            var count = await originalRequest.ReadAtLeastAsync(bytes, bytes.Length, false, deadline.Token);
            audit.RequestBytes = count;
            if (count > McpAuditPayload.MaxRequestBytes)
            {
                audit.RequestBodyOmittedReason = "REQUEST_LIMIT";
                await Reject(http, audit, 413, McpAuditResult.ProtocolError, "REQUEST_TOO_LARGE", "MCP 请求不得超过 32 KiB。");
                return;
            }
            audit.ReadRequest(bytes.AsMemory(0, count));
            if (audit.HasDuplicateRequestFields)
            {
                await Reject(http, audit, 400, McpAuditResult.ProtocolError, "DUPLICATE_FIELDS", "MCP 请求不能包含重复的 JSON 字段。");
                return;
            }
            using var requestCopy = new MemoryStream(bytes, 0, count, writable: false);
            request.Body = requestCopy;
            await next(http);
        }
        catch (OperationCanceledException) when (deadline.IsCancellationRequested)
        {
            audit.Result = McpAuditResult.Unknown;
            audit.ErrorCode = originalAbort.IsCancellationRequested ? "CLIENT_DISCONNECTED" : "REQUEST_TIMEOUT";
            if (!originalAbort.IsCancellationRequested && !response.HasStarted)
                await Reject(http, audit, 504, McpAuditResult.Unknown, "REQUEST_TIMEOUT", "调用超时，写操作可能已开始执行。");
        }
        catch (BadHttpRequestException)
        {
            if (!response.HasStarted)
                await Reject(http, audit, 400, McpAuditResult.ProtocolError, "BAD_HTTP_REQUEST", "HTTP 请求无效。");
        }
        catch (Exception exception)
        {
            // 数据库或 SDK 的异常正文可能带输入值，只记异常类型和审计摘要。
            auditHealth.ReportFailure();
            logger.LogWarning("MCP request could not complete ({FailureType})", exception.GetType().Name);
            audit.Result = audit.PersistedAuditId is null ? McpAuditResult.Unavailable : McpAuditResult.Unknown;
            audit.ErrorCode = "MCP_UNAVAILABLE";
            if (!response.HasStarted && !originalAbort.IsCancellationRequested)
                await Reject(http, audit, 503, audit.Result, "MCP_UNAVAILABLE", "MCP 服务暂不可用。");
        }
        finally
        {
            request.Body = originalRequest;
            http.RequestAborted = originalAbort;
            response.Body = originalResponse;
            if (audit.PersistedAuditId is not null || admitted || limiter.TryRecordRejectedRequest())
            {
                using var writeTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
                try
                {
                    if (audit.RequestBytes > 0 && !admitted)
                        audit.RequestBodyOmittedReason ??= "REQUEST_NOT_ADMITTED";
                    var entry = audit.Snapshot(captured);
                    if (audit.PersistedAuditId is { } id)
                        await store.CompleteAuditAsync(id, entry, writeTimeout.Token);
                    else
                        await store.RecordAuditAsync(entry, writeTimeout.Token);
                    auditHealth.ReportSuccess();
                }
                catch (Exception exception)
                {
                    auditHealth.ReportFailure();
                    logger.LogWarning("MCP audit could not be persisted ({FailureType})", exception.GetType().Name);
                }
            }
            else
            {
                auditHealth.ReportDrop();
            }
            if (admitted && audit.Key is { } key)
            {
                using var touchTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(1));
                try { await store.TouchKeyAsync(key.Id, touchTimeout.Token); }
                catch (Exception exception)
                {
                    logger.LogDebug("MCP last use time could not be updated ({FailureType})", exception.GetType().Name);
                }
            }
        }
    }

    private static Task Reject(HttpContext http, McpHttpAuditState audit, int status, string result, string code, string message)
    {
        audit.Result = result;
        audit.ErrorCode = code;
        audit.ErrorMessage = message;
        http.Response.StatusCode = status;
        return http.Response.WriteAsJsonAsync(new
        {
            jsonrpc = "2.0",
            id = (string?)null,
            error = new { code = -32000, message, data = new { code } },
        }, CancellationToken.None);
    }

    private bool IsAcceptedHost(HostString host, IPAddress? peer)
    {
        if (!host.HasValue) return false;
        var name = host.Host.Trim('[', ']');
        if (options.AllowedHosts.Contains(name, StringComparer.OrdinalIgnoreCase) ||
            options.AllowedHosts.Contains(host.Value, StringComparer.OrdinalIgnoreCase)) return true;
        return peer is not null && IPAddress.IsLoopback(peer) &&
            (name.Equals("localhost", StringComparison.OrdinalIgnoreCase) ||
                IPAddress.TryParse(name, out var ip) && IPAddress.IsLoopback(ip));
    }

    private static bool IsAcceptedOrigin(HttpRequest request)
    {
        if (!request.Headers.TryGetValue("Origin", out var origins)) return true;
        if (origins.Count != 1 || !Uri.TryCreate(origins[0], UriKind.Absolute, out var origin) ||
            !Uri.TryCreate(request.Scheme + "://" + request.Host.ToUriComponent(), UriKind.Absolute, out var endpoint))
            return false;
        return origin.UserInfo.Length == 0 && origin.AbsolutePath == "/" && origin.Query.Length == 0 && origin.Fragment.Length == 0 &&
            origin.Scheme == endpoint.Scheme && origin.IdnHost.Equals(endpoint.IdnHost, StringComparison.OrdinalIgnoreCase) &&
            origin.Port == endpoint.Port;
    }

    private static string? BearerToken(HttpRequest request)
    {
        if (!request.Headers.TryGetValue("Authorization", out var values) || values.Count != 1) return null;
        var header = values[0];
        return header?.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase) == true ? header[7..].Trim() : null;
    }
}
