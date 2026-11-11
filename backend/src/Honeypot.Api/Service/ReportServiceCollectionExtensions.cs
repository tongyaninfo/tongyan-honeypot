using Honeypot.Api.Service.impl;
using Honeypot.Api.Workers;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Honeypot.Api.Service;

public static class ReportServiceCollectionExtensions
{
    /// <summary>在数据库初始化注册之后、SignalR 装饰器之前调用；复用原事件与认证证据仓库。</summary>
    public static IServiceCollection AddHoneypotReports(this IServiceCollection services)
    {
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<InMemoryInteractionEventStore>();
        services.AddSingleton<ReportIngestionHealth>();
        services.AddSingleton<IInteractionEventStore, ReportInteractionEventStore>();
        services.AddSingleton<IReportService, SqliteReportService>();
        services.AddHostedService<ReportRuntimeSamplerWorker>();
        return services;
    }
}
