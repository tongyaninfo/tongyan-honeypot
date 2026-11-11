using Honeypot.Api.Options;
using Honeypot.Api.Service.impl;
using Honeypot.Api.Workers;

namespace Honeypot.Api.Service;

public static class IPLocationServiceCollectionExtensions
{
    public static IServiceCollection AddIPLocation(this IServiceCollection services)
    {
        services.AddSingleton(TimeProvider.System);
        services.AddSingleton<IPLocationOptions>();
        services.AddSingleton<IIPLocationSettingsStore, FileIPLocationSettingsStore>();
        services.AddSingleton<IIPLocation>(_ => new TongYanIPLocation(new HttpClient(new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false,
            MaxConnectionsPerServer = 4,
            PooledConnectionLifetime = TimeSpan.FromMinutes(2),
            MaxResponseHeadersLength = 16,
        }) { Timeout = Timeout.InfiniteTimeSpan }));
        services.AddSingleton<IPLocationResolver>();
        services.AddSingleton<IIPLocationResolver>(provider => provider.GetRequiredService<IPLocationResolver>());
        services.AddHostedService<IPLocationWorker>();
        return services;
    }
}
