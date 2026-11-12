using System.Net;
using Honeypot.Api.Common;
using Honeypot.Protocol.Abstractions.Models;
using Honeypot.Protocol.Abstractions.Service;

namespace Honeypot.Api.Service.impl;

public enum ServiceInstanceAction { Apply, Start, Stop, SetRestartPolicy }

public sealed record ServiceInstanceOperationResult(ServiceInstance? Instance, ListenerApplyResult? ListenerResult = null,
    string? AccessDeniedCode = null);

/// <summary>运行时维护共享监听表，统一串行保存和启停，避免两个入口对同一快照同时生效。</summary>
public sealed class ServiceInstanceOperations(IServiceInstanceStore store, IListenerHost listenerHost,
    IRealtimeUpdateNotifier notifier, IConfiguration configuration)
{
    private readonly SemaphoreSlim _operationGate = new(1, 1);
    private readonly IReadOnlySet<IPAddress> _allowedMcpBindAddresses = configuration
        .GetSection("Honeypot:Mcp:AllowedInstanceBindAddresses").GetChildren()
        .Select(setting => IPAddress.TryParse(setting.Value, out var address) ? McpInstanceScope.Normalize(address) : null)
        .OfType<IPAddress>().ToHashSet();

    public async Task<ServiceInstance> SaveAsync(ServiceInstance instance, CancellationToken cancellationToken)
    {
        await _operationGate.WaitAsync(cancellationToken);
        try { return store.Upsert(instance); }
        finally { _operationGate.Release(); }
    }

    public async Task<ServiceInstanceOperationResult> ExecuteAsync(string instanceId, ServiceInstanceAction action,
        CancellationToken cancellationToken, bool autoStart = false, string? authorizedBindingFingerprint = null)
    {
        await _operationGate.WaitAsync(cancellationToken);
        try
        {
            var instance = store.Get(instanceId);
            if (instance is null) return new(null);

            var activates = action == ServiceInstanceAction.Start || (action == ServiceInstanceAction.SetRestartPolicy && autoStart);
            if (authorizedBindingFingerprint is not null && activates)
            {
                if (!string.Equals(authorizedBindingFingerprint, McpInstanceScope.BindingFingerprint(instance), StringComparison.Ordinal))
                    return new(instance, AccessDeniedCode: "INSTANCE_BINDINGS_CHANGED");
                if (!McpInstanceScope.CanActivate(instance, _allowedMcpBindAddresses))
                    return new(instance, AccessDeniedCode: "INSTANCE_BINDINGS_NOT_ISOLATED");
            }

            switch (action)
            {
                case ServiceInstanceAction.SetRestartPolicy:
                    return new(store.SetDesiredState(instanceId, instance.DesiredState, autoStart));
                case ServiceInstanceAction.Stop:
                    await listenerHost.StopInstanceAsync(instanceId, cancellationToken);
                    store.SetDesiredState(instanceId, "Stopped");
                    var stopped = store.SetRuntimeState(instanceId, "Stopped");
                    await notifier.PublishRuntimeAsync(listenerHost.GetStatuses(), cancellationToken);
                    return new(stopped);
                case ServiceInstanceAction.Apply:
                case ServiceInstanceAction.Start:
                    var result = await listenerHost.ApplyAsync(instance, cancellationToken);
                    if (action == ServiceInstanceAction.Start)
                    {
                        store.SetDesiredState(instanceId, "Running");
                        instance = store.SetRuntimeState(instanceId, result.Succeeded ? "Running" : "Failed", result.Succeeded ? null : result.Message)!;
                    }
                    await notifier.PublishRuntimeAsync(listenerHost.GetStatuses(), cancellationToken);
                    return new(instance, result);
                default:
                    throw new ArgumentOutOfRangeException(nameof(action));
            }
        }
        finally { _operationGate.Release(); }
    }
}
