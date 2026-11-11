using Honeypot.Api.Service.impl;

namespace Honeypot.Api.Workers;

/// <summary>与协议监听和事件存储分离的固定并发后台任务。</summary>
public sealed class IPLocationWorker(IPLocationResolver resolver) : BackgroundService
{
    protected override Task ExecuteAsync(CancellationToken stoppingToken) => resolver.RunAsync(stoppingToken);
}
