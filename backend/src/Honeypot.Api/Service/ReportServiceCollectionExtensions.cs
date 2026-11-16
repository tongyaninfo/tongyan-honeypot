using Honeypot.Api.Data;
using Honeypot.Api.Options;
using Honeypot.Api.Service.impl;
using Honeypot.Api.Workers;
using Honeypot.Engine.Service;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Honeypot.Api.Service;

public static class ReportServiceCollectionExtensions
{
    /// <summary>在数据库初始化注册之后、SignalR 装饰器之前接入事务写入和留存清理。</summary>
    public static IServiceCollection AddHoneypotReports(this IServiceCollection services)
    {
        services.TryAddSingleton(TimeProvider.System);
        services.AddOptions<EventStorageOptions>()
            .BindConfiguration(EventStorageOptions.SectionName)
            .ValidateDataAnnotations()
            .ValidateOnStart();
        services.AddSingleton<SqliteThreatProfileStore>();
        services.AddSingleton<IThreatProfileStore>(provider => provider.GetRequiredService<SqliteThreatProfileStore>());
        services.AddSingleton<ReportIngestionHealth>();
        services.AddSingleton<ReportEventDiskBudget>();
        services.AddSingleton<ReportInteractionEventStore>();
        services.AddSingleton<IInteractionEventStore>(provider => provider.GetRequiredService<ReportInteractionEventStore>());
        services.AddHostedService<ReportEventWriterWorker>();
        services.AddHostedService<ReportEventRetentionWorker>();
        services.AddSingleton<IReportService, SqliteReportService>();
        services.AddHostedService<ReportRuntimeSamplerWorker>();
        return services;
    }
}
