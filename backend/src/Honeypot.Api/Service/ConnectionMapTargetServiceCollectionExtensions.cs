using Honeypot.Api.Service.impl;
using Honeypot.Api.Workers;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Honeypot.Api.Service;

public static class ConnectionMapTargetServiceCollectionExtensions
{
    public static IServiceCollection AddConnectionMapTarget(this IServiceCollection services)
    {
        services.TryAddSingleton(TimeProvider.System);
        services.AddSingleton(_ => new ConnectionMapPublicIpProbe(new HttpClient(new SocketsHttpHandler
        {
            // 探测实例的直接出口；不携带 Cookie、不跟随重定向，保留系统 TLS 校验。
            UseProxy = false,
            UseCookies = false,
            AllowAutoRedirect = false,
            MaxConnectionsPerServer = 1,
            MaxResponseHeadersLength = 16,
            PooledConnectionLifetime = TimeSpan.FromMinutes(2),
        }) { Timeout = Timeout.InfiniteTimeSpan }));
        services.AddSingleton<ConnectionMapTargetCache>();
        services.AddSingleton<ConnectionMapTargetWorker>();
        services.AddSingleton<IConnectionMapTarget>(provider => provider.GetRequiredService<ConnectionMapTargetWorker>());
        services.AddHostedService(provider => provider.GetRequiredService<ConnectionMapTargetWorker>());
        return services;
    }
}
