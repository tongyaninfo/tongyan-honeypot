using Honeypot.Protocol.Abstractions.Service;
using Microsoft.Extensions.DependencyInjection;

namespace Honeypot.Runtime.Service;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddHoneypotRuntime(this IServiceCollection services)
    {
        services.AddSingleton<IInteractionEventSink, InMemoryInteractionEventSink>();
        return services.AddHoneypotRuntimeCore();
    }
}
