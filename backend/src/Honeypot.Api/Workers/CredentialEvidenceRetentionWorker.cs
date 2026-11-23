using Honeypot.Api.Data;
using Honeypot.Api.Data.Models;
using Honeypot.Api.Options;
using Honeypot.Api.Service.impl;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Honeypot.Api.Workers;

/// <summary>凭据和访问审计分别清理，每次写事务只删除一批记录。</summary>
public sealed class CredentialEvidenceRetentionWorker(IDbContextFactory<HoneypotDbContext> factory, TimeProvider clock,
    IOptions<CredentialEvidenceOptions> options, ILogger<CredentialEvidenceRetentionWorker> logger, ReportIngestionHealth? health = null) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromMinutes(1), clock);
        do
        {
            try { await RunOnceAsync(stoppingToken); health?.RecoverStage("retention.evidence"); }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { return; }
            catch (Exception error)
            {
                var code = ReportIngestionHealth.Classify(error);
                health?.RecordStageFault("retention.evidence", code);
                logger.LogWarning("Credential evidence retention failed. ErrorCode={ErrorCode}", code);
            }
        } while (await timer.WaitForNextTickAsync(stoppingToken));
    }

    public async Task RunOnceAsync(CancellationToken cancellationToken)
    {
        const int evidenceBatchSize = 32;
        const int auditBatchSize = 250;
        var now = clock.GetUtcNow();
        var auditCutoff = now.AddDays(-options.Value.AuditRetentionDays).UtcTicks;
        await using var db = await factory.CreateDbContextAsync(cancellationToken);
        SqliteCredentialEvidenceStore.SetTimeout(db);
        for (var batch = 0; batch < 10; batch++)
        {
            if (batch > 0 && health?.EventQueueDepth > 0) break;
            var evidence = db.Set<CredentialEvidenceEntity>();
            var expiredEvidence = evidence.Where(row => row.RetentionUntilUtcTicks <= now.UtcTicks)
                .OrderBy(row => row.RetentionUntilUtcTicks).ThenBy(row => row.ArtifactId).Take(evidenceBatchSize).Select(row => row.ArtifactId);
            var evidenceCount = await evidence.Where(row => expiredEvidence.Contains(row.ArtifactId)).ExecuteDeleteAsync(cancellationToken);

            var audits = db.Set<CredentialEvidenceAccessAuditEntity>();
            var expiredAudits = audits.Where(row => row.OccurredAtUtcTicks <= auditCutoff)
                .OrderBy(row => row.OccurredAtUtcTicks).ThenBy(row => row.AuditId).Take(auditBatchSize).Select(row => row.AuditId);
            var auditCount = await audits.Where(row => expiredAudits.Contains(row.AuditId)).ExecuteDeleteAsync(cancellationToken);
            if (evidenceCount < evidenceBatchSize && auditCount < auditBatchSize) break;
            await Task.Delay(TimeSpan.FromMilliseconds(50), cancellationToken);
        }
    }
}
