using Honeypot.Protocol.Abstractions.Service;
using Microsoft.Extensions.DependencyInjection;

namespace Honeypot.Runtime.Service;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddHoneypotRuntime(this IServiceCollection services)
    {
        services.AddSingleton<IProtocolAdapterRegistry, ProtocolAdapterRegistry>();
        services.AddSingleton<IConnectionIdGenerator, ConnectionIdGenerator>();
        services.AddSingleton<IInteractionEventSink, InMemoryInteractionEventSink>();
        services.AddSingleton<IListenerHost, TcpListenerHost>();
        return services;
    }
}
