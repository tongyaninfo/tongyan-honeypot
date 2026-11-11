using Honeypot.Protocol.Abstractions.Models;

namespace Honeypot.Api.Service;

public interface IServiceInstanceStore
{
    ServiceInstance Upsert(ServiceInstance instance);

    IReadOnlyCollection<ServiceInstance> GetAll();

    ServiceInstance? Get(string instanceId);

    ServiceInstance? SetRuntimeState(string instanceId, string currentState, string? lastError = null);

    ServiceInstance? SetDesiredState(string instanceId, string desiredState, bool? autoStart = null);
}
