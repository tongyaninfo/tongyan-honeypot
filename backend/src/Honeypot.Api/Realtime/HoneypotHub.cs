using Honeypot.Api.Service;
using Honeypot.Protocol.Abstractions.Models;
using Honeypot.Protocol.Abstractions.Service;
using Honeypot.Shared.Models;
using Microsoft.AspNetCore.SignalR;

namespace Honeypot.Api.Realtime;

/// <summary>
/// 蜜罐管理台实时通道。项目使用文件会话身份服务，因此不能依赖默认 JWT handler，
/// 而是在握手时复用当前 HTTP Bearer 会话令牌。
/// </summary>
public sealed class HoneypotHub : Hub
{
    private readonly IUserIdentityService _identity;
    private readonly IListenerHost _listenerHost;

    public HoneypotHub(IUserIdentityService identity, IListenerHost listenerHost)
    {
        _identity = identity;
        _listenerHost = listenerHost;
    }

    public override async Task OnConnectedAsync()
    {
        var httpContext = Context.GetHttpContext();
        var token = ReadAccessToken(httpContext);
        if (string.IsNullOrWhiteSpace(token) ||
            !_identity.IsInitialized ||
            !_identity.TryAuthenticate(token, out var user) ||
            user is null)
        {
            // SignalR 握手不经过 /api 自定义中间件，必须在 Hub 内再次校验会话。
            Context.Abort();
            return;
        }

        Context.Items["CurrentUser"] = user;
        await base.OnConnectedAsync();
    }

    /// <summary>
    /// 连接成功后的可选快照接口，前端仍以 REST 快照为主，避免断线重连期间丢数据。
    /// </summary>
    public ApiResult<IReadOnlyCollection<ListenerRuntimeStatus>> GetRuntimeSnapshot()
    {
        return ApiResult<IReadOnlyCollection<ListenerRuntimeStatus>>.Ok(_listenerHost.GetStatuses());
    }

    private static string? ReadAccessToken(HttpContext? httpContext)
    {
        if (httpContext is null)
        {
            return null;
        }

        var authorization = httpContext.Request.Headers.Authorization.ToString();
        if (authorization.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            return authorization[7..].Trim();
        }

        // 浏览器 WebSocket 无法自定义 Authorization 头时，SignalR 会使用 access_token 查询参数。
        // 只允许在本 Hub 的精确路径启用，避免把查询参数误当作其它 API 的凭据。
        if (string.Equals(httpContext.Request.Path.Value, "/hubs/honeypot", StringComparison.OrdinalIgnoreCase))
        {
            return httpContext.Request.Query["access_token"].FirstOrDefault();
        }

        return null;
    }
}
