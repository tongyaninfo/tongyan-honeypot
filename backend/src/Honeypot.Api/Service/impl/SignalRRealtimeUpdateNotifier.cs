using Honeypot.Api.Models;
using Honeypot.Api.Realtime;
using Honeypot.Protocol.Abstractions.Models;
using Honeypot.Shared.Models;
using Microsoft.AspNetCore.SignalR;

namespace Honeypot.Api.Service.impl;

/// <summary>
/// SignalR 广播实现。所有消息均包裹 ApiResult，且事件使用安全视图，不把密码原文推给前端。
/// </summary>
public sealed class SignalRRealtimeUpdateNotifier : IRealtimeUpdateNotifier
{
    private readonly IHubContext<HoneypotHub> _hubContext;
    private readonly ILogger<SignalRRealtimeUpdateNotifier> _logger;
    private readonly ISyslogPublisher? _logs;
    private int _consecutiveFailures;

    public SignalRRealtimeUpdateNotifier(
        IHubContext<HoneypotHub> hubContext,
        ILogger<SignalRRealtimeUpdateNotifier> logger,
        ISyslogPublisher? logs = null)
    {
        _hubContext = hubContext;
        _logger = logger;
        _logs = logs;
    }

    public Task PublishEventAsync(
        InteractionEvent interactionEvent,
        CancellationToken cancellationToken = default)
    {
        var payload = ApiResult<RealtimeInteractionEvent>.Ok(
            RealtimeInteractionEvent.From(interactionEvent),
            "event appended");
        return SendSafelyAsync("eventAppended", payload, cancellationToken);
    }

    public Task PublishRuntimeAsync(
        IReadOnlyCollection<ListenerRuntimeStatus> statuses,
        CancellationToken cancellationToken = default)
    {
        var payload = ApiResult<IReadOnlyCollection<ListenerRuntimeStatus>>.Ok(statuses, "runtime changed");
        return SendSafelyAsync("runtimeChanged", payload, cancellationToken);
    }

    private async Task SendSafelyAsync<T>(
        string method,
        T payload,
        CancellationToken cancellationToken)
    {
        try
        {
            await _hubContext.Clients.All.SendAsync(method, payload, cancellationToken);
            if (Interlocked.Exchange(ref _consecutiveFailures, 0) >= 3)
                _logs?.Publish("honeypot-realtime", "REALTIME_BROADCAST_RECOVERED", SyslogSeverity.Notice);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // 请求取消只表示当前广播不再需要，不影响事件记录。
        }
        catch (Exception exception)
        {
            // 实时通道是旁路能力，连接断开时不能让监听器或事件管道失败。
            var failures = Interlocked.Increment(ref _consecutiveFailures);
            if (failures == 1) _logger.LogDebug("SignalR broadcast {Method} failed: {ExceptionType}", method, exception.GetType().Name);
            if (failures == 3 || failures % 50 == 0)
                _logs?.Publish("honeypot-realtime", "REALTIME_BROADCAST_DEGRADED", SyslogSeverity.Warning,
                    new Dictionary<string, object?> { ["method"] = method, ["failureCount"] = failures, ["exceptionType"] = exception.GetType().Name });
        }
    }
}
