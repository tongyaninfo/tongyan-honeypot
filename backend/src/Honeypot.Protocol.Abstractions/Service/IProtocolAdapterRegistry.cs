namespace Honeypot.Protocol.Abstractions.Service;

public interface IProtocolAdapterRegistry
{
    void Register(IHoneypotServiceAdapter adapter);

    bool TryGet(string adapterKey, out IHoneypotServiceAdapter? adapter);

    IHoneypotServiceAdapter GetRequired(string adapterKey);

    IReadOnlyCollection<IHoneypotServiceAdapter> GetAll();
}
