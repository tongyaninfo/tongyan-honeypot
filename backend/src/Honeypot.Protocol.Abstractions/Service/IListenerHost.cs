using Honeypot.Protocol.Abstractions.Models;

namespace Honeypot.Protocol.Abstractions.Service;

public interface IListenerHost : IAsyncDisposable
{
    IReadOnlyCollection<ListenerRuntimeStatus> GetStatuses();

    Task<ListenerApplyResult> ApplyAsync(ServiceInstance instance, CancellationToken cancellationToken = default);

    Task StopInstanceAsync(string instanceId, CancellationToken cancellationToken = default);

    Task StopAsync(CancellationToken cancellationToken = default);
}
