using Honeypot.Api.Service.impl;
using Honeypot.Api.Workers;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Honeypot.Api.Service;

public static class McpPersistenceServiceCollectionExtensions
{
    public static IServiceCollection AddHoneypotMcpPersistence(this IServiceCollection services)
    {
        services.TryAddSingleton(TimeProvider.System);
        services.AddSingleton<McpAuditHealth>();
        services.AddSingleton<SqliteMcpStore>();
        services.AddSingleton<IMcpStore>(provider => provider.GetRequiredService<SqliteMcpStore>());
        services.AddHostedService<McpAuditRetentionWorker>();
        return services;
    }
}
