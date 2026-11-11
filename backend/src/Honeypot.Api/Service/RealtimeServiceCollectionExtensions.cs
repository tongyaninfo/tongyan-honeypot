using Honeypot.Api.Realtime;
using Honeypot.Api.Service.impl;
using Honeypot.Api.Workers;
using Honeypot.Protocol.Abstractions.Service;
using Honeypot.Protocols.Common;
using Microsoft.Extensions.DependencyInjection;

namespace Honeypot.Api.Service;

/// <summary>
/// 注册 SignalR 实时通道。调用方应在 IInteractionEventStore 注册之后调用此扩展，
/// 让事件入口由 RealtimeInteractionEventSink 接管。
/// </summary>
public static class RealtimeServiceCollectionExtensions
{
    public static IServiceCollection AddHoneypotRealtime(this IServiceCollection services)
    {
        services.AddSignalR();
        services.AddSingleton<IRealtimeUpdateNotifier, SignalRRealtimeUpdateNotifier>();
        services.AddSingleton<ICredentialEvidenceSink>(provider =>
            provider.GetRequiredService<IInteractionEventStore>() as ICredentialEvidenceSink
            ?? throw new InvalidOperationException("IInteractionEventStore must implement ICredentialEvidenceSink."));
        services.AddSingleton<IInteractionEventSink>(provider =>
            new RealtimeInteractionEventSink(
                provider.GetRequiredService<IInteractionEventStore>(),
                provider.GetRequiredService<ICredentialEvidenceSink>(),
                provider.GetRequiredService<IRealtimeUpdateNotifier>(),
                provider.GetRequiredService<ILogger<RealtimeInteractionEventSink>>(),
                provider.GetService<ISyslogPublisher>()));
        services.AddHostedService<RealtimeSnapshotWorker>();
        return services;
    }
}
