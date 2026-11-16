using Honeypot.Api.Service.impl;

namespace Honeypot.Api.Workers;

/// <summary>所有公网事件共用一个 SQLite 写入消费者，停机时先结束入队再处理现有队列。</summary>
public sealed class ReportEventWriterWorker(ReportInteractionEventStore store) : BackgroundService
{
    protected override Task ExecuteAsync(CancellationToken stoppingToken) => store.WriteQueuedEventsAsync(stoppingToken);

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        store.CompleteQueue();
        try
        {
            if (ExecuteTask is { } execution)
                await execution.WaitAsync(cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }
        finally { await base.StopAsync(cancellationToken); }
    }
}
