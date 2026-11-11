using Honeypot.Api.Service;
using Honeypot.Protocol.Abstractions.Service;
using Honeypot.Shared.Models;

namespace Honeypot.Api.Workers;

/// <summary>
/// 恢复数据库中的实例配置。只有显式开启自动启动且期望状态为 Running 的实例才会重新绑定端口。
/// </summary>
public sealed class ServiceInstanceRecoveryWorker : IHostedService
{
    private readonly IServiceInstanceStore _store;
    private readonly IListenerHost _listenerHost;
    private readonly ILogger<ServiceInstanceRecoveryWorker> _logger;
    private readonly ISyslogPublisher? _logs;

    public ServiceInstanceRecoveryWorker(
        IServiceInstanceStore store,
        IListenerHost listenerHost,
        ILogger<ServiceInstanceRecoveryWorker> logger,
        ISyslogPublisher? logs = null)
    {
        _store = store;
        _listenerHost = listenerHost;
        _logger = logger;
        _logs = logs;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        var requested = 0;
        var failed = 0;
        foreach (var instance in _store.GetAll())
        {
            _store.SetRuntimeState(instance.InstanceId, "Stopped");
            if (!instance.AutoStart || !string.Equals(instance.DesiredState, "Running", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            requested++;
            try
            {
                var result = await _listenerHost.ApplyAsync(instance, cancellationToken);
                _store.SetRuntimeState(instance.InstanceId, result.Succeeded ? "Running" : "Failed", result.Succeeded ? null : result.Message);
                if (!result.Succeeded)
                {
                    failed++;
                    _logger.LogError("恢复蜜罐实例 {InstanceId} 失败：{ErrorCode}", instance.InstanceId, result.Code);
                }
                else _logs?.Publish("honeypot-runtime", "SERVICE_INSTANCE_RECOVERED", SyslogSeverity.Notice,
                    new Dictionary<string, object?> { ["serviceInstanceId"] = instance.InstanceId });
            }
            catch (Exception exception) when (exception is not OperationCanceledException)
            {
                failed++;
                _store.SetRuntimeState(instance.InstanceId, "Failed", exception.Message);
                _logger.LogError("恢复蜜罐实例 {InstanceId} 时发生异常：{ExceptionType}。", instance.InstanceId, exception.GetType().Name);
            }
        }
        if (requested > 0 && failed == requested)
            _logs?.Publish("honeypot-runtime", "ALL_INSTANCE_RECOVERY_FAILED", SyslogSeverity.Critical,
                new Dictionary<string, object?> { ["failureCount"] = failed });
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        await _listenerHost.StopAsync(cancellationToken);
        // 进程退出后端口已不再监听，先把数据库中的运行态同步为 Stopped；
        // DesiredState/AutoStart 保留，用于下次启动时决定是否恢复。
        foreach (var instance in _store.GetAll())
        {
            _store.SetRuntimeState(instance.InstanceId, "Stopped");
        }
    }
}
