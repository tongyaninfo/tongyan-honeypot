using Honeypot.Protocol.Abstractions.Service;

namespace Honeypot.Runtime.Service;

public sealed class ProtocolAdapterRegistry : IProtocolAdapterRegistry
{
    private readonly object _sync = new();
    private readonly Dictionary<string, IHoneypotServiceAdapter> _adapters = new(StringComparer.OrdinalIgnoreCase);

    public void Register(IHoneypotServiceAdapter adapter)
    {
        ArgumentNullException.ThrowIfNull(adapter);
        var key = adapter.Descriptor.AdapterKey.Trim();
        if (key.Length == 0)
        {
            throw new ArgumentException("AdapterKey cannot be empty.", nameof(adapter));
        }

        lock (_sync)
        {
            if (!_adapters.TryAdd(key, adapter))
            {
                throw new InvalidOperationException($"Protocol adapter '{key}' is already registered.");
            }
        }
    }

    public bool TryGet(string adapterKey, out IHoneypotServiceAdapter? adapter)
    {
        lock (_sync)
        {
            return _adapters.TryGetValue(adapterKey, out adapter);
        }
    }

    public IHoneypotServiceAdapter GetRequired(string adapterKey) =>
        TryGet(adapterKey, out var adapter) && adapter is not null
            ? adapter
            : throw new KeyNotFoundException($"Protocol adapter '{adapterKey}' is not registered.");

    public IReadOnlyCollection<IHoneypotServiceAdapter> GetAll()
    {
        lock (_sync)
        {
            return _adapters.Values.ToArray();
        }
    }
}
