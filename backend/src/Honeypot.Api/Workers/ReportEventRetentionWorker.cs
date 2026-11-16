using Honeypot.Api.Data;
using Honeypot.Api.Data.Models;
using Honeypot.Api.Options;
using Honeypot.Api.Service.impl;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Honeypot.Api.Workers;

/// <summary>按各自留存策略清理过期采集记录和管理操作审计。</summary>
public sealed class ReportEventRetentionWorker(
    IDbContextFactory<HoneypotDbContext> factory,
    IOptions<EventStorageOptions> options,
    ReportIngestionHealth health,
    TimeProvider time,
    ReportEventDiskBudget diskBudget,
    ILogger<ReportEventRetentionWorker> logger) : BackgroundService
{
    private const int BatchSize = 1000;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromMinutes(1), time);
        do
        {
            try
            {
                await RunOnceAsync(stoppingToken);
                health.SetRetentionAvailable(true);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (Exception error)
            {
                health.SetRetentionAvailable(false);
                logger.LogWarning("Report event retention failed. ExceptionType={ExceptionType}", error.GetType().Name);
            }
        } while (await timer.WaitForNextTickAsync(stoppingToken));
    }

    public async Task RunOnceAsync(CancellationToken cancellationToken)
    {
        var now = time.GetUtcNow();
        var cutoff = now.AddDays(-options.Value.ReportRetentionDays).ToUnixTimeMilliseconds();
        var detailsCutoff = now.AddDays(-options.Value.DetailRetentionDays).ToUnixTimeMilliseconds();
        var auditsCutoff = now.AddDays(-options.Value.AuditRetentionDays).ToUnixTimeMilliseconds();
        for (var batch = 0; batch < 10; batch++)
        {
            if (!await PruneExpiredAsync(cutoff, detailsCutoff, now.ToUnixTimeMilliseconds(), auditsCutoff, cancellationToken)) break;
            await Task.Delay(TimeSpan.FromMilliseconds(50), cancellationToken);
        }

        await using var db = await factory.CreateDbContextAsync(cancellationToken);
        await db.Database.OpenConnectionAsync(cancellationToken);
        await ReportEventDiskBudget.CheckpointAsync(db, cancellationToken);
        await diskBudget.CanWriteAsync(db, options.Value, health, cancellationToken);
    }

    private async Task<bool> PruneExpiredAsync(long cutoff, long detailsCutoff, long now, long auditsCutoff,
        CancellationToken cancellationToken)
    {
        await using var db = await factory.CreateDbContextAsync(cancellationToken);
        db.Database.SetCommandTimeout(2);
        var events = db.Set<ReportEventEntity>();
        var eventCount = await events.Where(item => item.OccurredAtUnixMs < cutoff)
            .OrderBy(item => item.OccurredAtUnixMs).Take(BatchSize).ExecuteDeleteAsync(cancellationToken);
        var samples = await db.Set<ReportRuntimeSampleEntity>().Where(sample => sample.CapturedAtUnixMs < cutoff)
            .OrderBy(sample => sample.CapturedAtUnixMs).Take(BatchSize).ExecuteDeleteAsync(cancellationToken);
        // 仍有保留事实的 IP 保留真正首次时间，确保当前报告周期不会重复计为新来源。
        var sources = await db.Set<ReportSourceFirstSeenEntity>()
            .Where(source => source.FirstSeenAtUnixMs < cutoff && !events.Any(item => item.SourceIp == source.SourceIp))
            .OrderBy(source => source.FirstSeenAtUnixMs).Take(BatchSize).ExecuteDeleteAsync(cancellationToken);
        var details = await db.Set<InteractionEventEntity>().Where(item => item.ReceivedAtUnixMs <= detailsCutoff)
            .OrderBy(item => item.ReceivedAtUnixMs).Take(BatchSize).ExecuteDeleteAsync(cancellationToken);
        var threats = await db.Set<ThreatProfileEntity>().Where(item => item.ExpiresAtUnixMs <= now)
            .OrderBy(item => item.ExpiresAtUnixMs).Take(BatchSize).ExecuteDeleteAsync(cancellationToken);
        var audits = await db.Set<ManagementOperationAuditEntity>().Where(item => item.OccurredAtUnixMs < auditsCutoff)
            .OrderBy(item => item.OccurredAtUnixMs).Take(BatchSize).ExecuteDeleteAsync(cancellationToken);
        return eventCount == BatchSize || samples == BatchSize || sources == BatchSize || details == BatchSize ||
            threats == BatchSize || audits == BatchSize;
    }
}
