using System.Collections.Concurrent;
using Honeypot.Protocol.Abstractions.Models;

namespace Honeypot.Api.Service.impl;

public sealed class InMemoryServiceInstanceStore : IServiceInstanceStore
{
    private readonly ConcurrentDictionary<string, ServiceInstance> _instances = new(StringComparer.OrdinalIgnoreCase);

    public ServiceInstance Upsert(ServiceInstance instance)
    {
        ArgumentNullException.ThrowIfNull(instance);
        _instances[instance.InstanceId] = instance;
        return instance;
    }

    public IReadOnlyCollection<ServiceInstance> GetAll() => _instances.Values.OrderBy(item => item.InstanceId).ToArray();

    public ServiceInstance? Get(string instanceId) =>
        _instances.TryGetValue(instanceId, out var instance) ? instance : null;

    public ServiceInstance? SetRuntimeState(string instanceId, string currentState, string? lastError = null)
    {
        if (!_instances.TryGetValue(instanceId, out var instance))
        {
            return null;
        }

        var updated = instance with { CurrentState = currentState, LastError = lastError };
        _instances[instanceId] = updated;
        return updated;
    }

    public ServiceInstance? SetDesiredState(string instanceId, string desiredState, bool? autoStart = null)
    {
        if (!_instances.TryGetValue(instanceId, out var instance))
        {
            return null;
        }

        var updated = instance with
        {
            DesiredState = desiredState,
            AutoStart = autoStart ?? instance.AutoStart,
        };
        _instances[instanceId] = updated;
        return updated;
    }
}
