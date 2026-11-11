using Honeypot.Api.Service;
using Honeypot.Protocol.Abstractions.Models;
using Honeypot.Protocol.Abstractions.Service;

namespace Honeypot.Api.Workers;

/// <summary>
/// 定时广播监听器快照，覆盖启动、停止、失败和连接计数变化。
/// </summary>
public sealed class RealtimeSnapshotWorker : BackgroundService
{
    private readonly IListenerHost _listenerHost;
    private readonly IRealtimeUpdateNotifier _notifier;
    private readonly ILogger<RealtimeSnapshotWorker> _logger;

    public RealtimeSnapshotWorker(
        IListenerHost listenerHost,
        IRealtimeUpdateNotifier notifier,
        ILogger<RealtimeSnapshotWorker> logger)
    {
        _listenerHost = listenerHost;
        _notifier = notifier;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        string? lastFingerprint = null;
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(1));

        while (await timer.WaitForNextTickAsync(stoppingToken))
        {
            try
            {
                var statuses = _listenerHost.GetStatuses();
                var fingerprint = BuildFingerprint(statuses);
                if (string.Equals(fingerprint, lastFingerprint, StringComparison.Ordinal))
                {
                    continue;
                }

                lastFingerprint = fingerprint;
                await _notifier.PublishRuntimeAsync(statuses, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception exception)
            {
                // 轮询失败仅影响下一次实时快照，REST 查询和监听器仍可继续工作。
                _logger.LogError("Realtime runtime snapshot failed: {ExceptionType}", exception.GetType().Name);
            }
        }
    }

    private static string BuildFingerprint(IReadOnlyCollection<ListenerRuntimeStatus> statuses) =>
        string.Join("|", statuses
            .OrderBy(item => item.ListenerId, StringComparer.Ordinal)
            .Select(item => string.Join(
                ":",
                item.ListenerId,
                item.InstanceId,
                item.BindAddress,
                item.Port,
                item.Transport,
                item.State,
                item.ActiveConnections,
                item.AcceptedCount,
                item.ErrorCount,
                item.LastError)));
}
