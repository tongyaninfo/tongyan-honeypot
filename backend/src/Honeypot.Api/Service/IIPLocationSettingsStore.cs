using Honeypot.Shared.Models;

namespace Honeypot.Api.Service;

public interface IIPLocationSettingsStore
{
    IPLocationSettings Current { get; }
    event Action<IPLocationSettings>? Changed;
    Task SaveAsync(IPLocationSettings settings, CancellationToken cancellationToken);
}
