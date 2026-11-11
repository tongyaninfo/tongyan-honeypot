using System.Collections.Concurrent;
using Honeypot.Protocol.Abstractions.Models;
using Honeypot.Protocol.Abstractions.Service;

namespace Honeypot.Runtime.Service.impl;

public sealed class ProtocolAdapterRegistry : IProtocolAdapterRegistry
{
    private readonly ConcurrentDictionary<string, IHoneypotServiceAdapter> _adapters = new(StringComparer.OrdinalIgnoreCase);

    public void Register(IHoneypotServiceAdapter adapter)
    {
        ArgumentNullException.ThrowIfNull(adapter);
        _adapters[adapter.Descriptor.AdapterKey] = adapter;
    }

    public bool TryGet(string adapterKey, out IHoneypotServiceAdapter? adapter) =>
        _adapters.TryGetValue(adapterKey, out adapter);

    public IHoneypotServiceAdapter GetRequired(string adapterKey) =>
        _adapters.TryGetValue(adapterKey, out var adapter)
            ? adapter
            : throw new InvalidOperationException($"Adapter '{adapterKey}' is not registered.");

    public IReadOnlyCollection<IHoneypotServiceAdapter> GetAll() => _adapters.Values.OrderBy(item => item.Descriptor.AdapterKey).ToArray();
}
