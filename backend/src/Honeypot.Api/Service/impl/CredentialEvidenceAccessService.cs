using System.Collections.Concurrent;
using Honeypot.Api.Common;
using Honeypot.Api.Data;
using Honeypot.Api.Data.Models;
using Honeypot.Api.Models;
using Honeypot.Api.Options;
using Honeypot.Shared.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Honeypot.Api.Service.impl;

/// <summary>原文访问在服务端检查当前角色，持久化审计完成后才返回。</summary>
public sealed class CredentialEvidenceAccessService(ICredentialEvidenceStore store, ISyslogPublisher? syslog = null,
    IResourceIdGenerator? ids = null, IDbContextFactory<HoneypotDbContext>? factory = null,
    TimeProvider? clock = null, IOptions<CredentialEvidenceOptions>? options = null,
    ILogger<CredentialEvidenceAccessService>? logger = null, ReportIngestionHealth? health = null)
    : ICredentialEvidenceAccessService
{
    private const int AuditViewLimit = 10_000;
    private readonly ConcurrentQueue<CredentialEvidenceAudit> _audits = new();
    private readonly TimeProvider _clock = clock ?? TimeProvider.System;

    public CredentialEvidenceReadResult Read(string artifactId, AuthenticatedUser? user) => Read(artifactId, user, "Read");

    public CredentialEvidenceReadResult ReadForExport(string artifactId, AuthenticatedUser? user) => Read(artifactId, user, "Export");

    public void AuditExportDenied(AuthenticatedUser? user) =>
        Audit("", user, user is null ? "UNAUTHORIZED" : "FORBIDDEN", "Export");

    private CredentialEvidenceReadResult Read(string artifactId, AuthenticatedUser? user, string operation)
    {
        CredentialEvidenceReadResult result;
        if (user is null) result = new(401, "UNAUTHORIZED", null);
        else if (!UserAuthorization.IsAdministrator(user)) result = new(403, "FORBIDDEN", null);
        else
        {
            try
            {
                var evidence = store.Get(artifactId);
                result = evidence is null ? new(404, "NOT_FOUND_OR_EXPIRED", null) : new(200, "OK", evidence);
            }
            catch (Exception)
            {
                // 解密或存储读取失败同样必须留审计，且不能将异常内容或部分原文返回调用方。
                result = new(500, "EVIDENCE_READ_FAILED", null);
            }
        }

        // 先记录审计再返回原文。每次符合路由的拒绝请求也需留痕。
        if (!Audit(artifactId, user, result.Code, operation) && result.Evidence is not null)
            return new(500, "EVIDENCE_AUDIT_FAILED", null);
        return result;
    }

    private bool Audit(string artifactId, AuthenticatedUser? user, string outcome, string operation)
    {
        if (factory is not null && user is null && operation == "Read" && !CredentialEvidenceEndpoints.IsEvidenceId(artifactId)) return false;

        // 任意路径输入不能原样进入持久审计或 Syslog。保留合法证据编号供运维关联。
        var auditArtifactId = factory is null || CredentialEvidenceEndpoints.IsEvidenceId(artifactId) ? artifactId : "";
        var audit = new CredentialEvidenceAudit(ids?.NewId() ?? Guid.NewGuid().ToString("N"), auditArtifactId,
            user?.UserId, _clock.GetUtcNow(), outcome, operation);
        if (factory is null)
        {
            _audits.Enqueue(audit);
        }
        else if (!TrySaveAudit(audit))
        {
            return false;
        }

        var severity = outcome switch
        {
            "OK" => SyslogSeverity.Notice,
            "UNAUTHORIZED" or "FORBIDDEN" => SyslogSeverity.Warning,
            "EVIDENCE_READ_FAILED" => SyslogSeverity.Error,
            _ => SyslogSeverity.Informational,
        };
        SyslogInteractionProjection.PublishSafely(syslog, "honeypot-evidence", "EVIDENCE_ACCESS", severity,
            new Dictionary<string, object?> { ["auditId"] = audit.AuditId, ["credentialArtifactId"] = auditArtifactId,
                ["actorUserId"] = user?.UserId, ["operation"] = operation, ["outcome"] = outcome,
                ["occurredAtUtc"] = audit.OccurredAtUtc });
        return true;
    }

    private bool TrySaveAudit(CredentialEvidenceAudit audit)
    {
        try
        {
            using var db = factory!.CreateDbContext();
            SqliteCredentialEvidenceStore.SetTimeout(db);
            db.Database.OpenConnection();

            db.Set<CredentialEvidenceAccessAuditEntity>().Add(new()
            {
                AuditId = audit.AuditId, ArtifactId = audit.CredentialArtifactId, UserId = audit.UserId,
                OccurredAtUtcTicks = audit.OccurredAtUtc.UtcTicks, Outcome = audit.Outcome, Operation = audit.Operation,
            });
            db.SaveChanges();
            health?.RecoverStage("evidence.audit");
            return true;
        }
        catch (Exception error)
        {
            // 审计失败时拒绝原文。避免数据库异常包含输入内容。
            var code = ReportIngestionHealth.Classify(error);
            health?.RecordStageFault("evidence.audit", code);
            logger?.LogWarning("Credential evidence audit write failed. ErrorCode={ErrorCode}", code);
            return false;
        }
    }

    public IReadOnlyCollection<CredentialEvidenceAudit> GetAuditTrail()
    {
        if (factory is null) return _audits.Reverse().ToArray();

        using var db = factory.CreateDbContext();
        SqliteCredentialEvidenceStore.SetTimeout(db);
        return ActiveAudits(db).Take(AuditViewLimit).ToArray();
    }

    public QueryPageResult<CredentialEvidenceAudit> GetAuditPage(int? page, int? pageSize)
    {
        if (factory is null) return QueryPage.Create(GetAuditTrail(), page, pageSize);
        using var db = factory.CreateDbContext();
        SqliteCredentialEvidenceStore.SetTimeout(db);
        var rows = ActiveAudits(db);
        var (number, size, offset) = QueryPage.Bounds(page, pageSize);
        var count = rows.Count();
        return new(offset < count ? rows.Skip((int)offset).Take(size).ToArray() : [], count, number, size);
    }

    private IQueryable<CredentialEvidenceAudit> ActiveAudits(HoneypotDbContext db)
    {
        var retentionDays = options?.Value.AuditRetentionDays ?? CredentialEvidenceOptions.DefaultAuditRetentionDays;
        var cutoff = _clock.GetUtcNow().AddDays(-retentionDays).UtcTicks;
        return db.Set<CredentialEvidenceAccessAuditEntity>().AsNoTracking().Where(row => row.OccurredAtUtcTicks > cutoff)
            .OrderByDescending(row => row.OccurredAtUtcTicks).ThenByDescending(row => row.AuditId)
            .Select(row => new CredentialEvidenceAudit(row.AuditId, row.ArtifactId, row.UserId,
                SqliteCredentialEvidenceStore.Utc(row.OccurredAtUtcTicks), row.Outcome, row.Operation));
    }

}
