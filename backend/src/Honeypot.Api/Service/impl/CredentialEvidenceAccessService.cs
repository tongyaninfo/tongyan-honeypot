using System.Collections.Concurrent;
using Honeypot.Api.Common;
using Honeypot.Api.Models;
using Honeypot.Shared.Models;

namespace Honeypot.Api.Service.impl;

/// <summary>原文访问在服务端检查当前角色；开发阶段审计保留在有界内存中。</summary>
public sealed class CredentialEvidenceAccessService(ICredentialEvidenceStore store, ISyslogPublisher? syslog = null,
    IResourceIdGenerator? ids = null) : ICredentialEvidenceAccessService
{
    private readonly ConcurrentQueue<CredentialEvidenceAudit> _audits = new();

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

        // 每次允许、拒绝或过期的访问均留痕，先记录审计再向调用方返回原文。
        Audit(artifactId, user, result.Code, operation);
        return result;
    }

    private void Audit(string artifactId, AuthenticatedUser? user, string outcome, string operation)
    {
        var audit = new CredentialEvidenceAudit(ids?.NewId() ?? Guid.NewGuid().ToString("N"), artifactId,
            user?.UserId, DateTimeOffset.UtcNow, outcome, operation);
        _audits.Enqueue(audit);
        while (_audits.Count > 10000) _audits.TryDequeue(out _);
        var severity = outcome switch
        {
            "OK" => SyslogSeverity.Notice,
            "UNAUTHORIZED" or "FORBIDDEN" => SyslogSeverity.Warning,
            "EVIDENCE_READ_FAILED" => SyslogSeverity.Error,
            _ => SyslogSeverity.Informational,
        };
        SyslogInteractionProjection.PublishSafely(syslog, "honeypot-evidence", "EVIDENCE_ACCESS", severity,
            new Dictionary<string, object?> { ["auditId"] = audit.AuditId, ["credentialArtifactId"] = artifactId,
                ["actorUserId"] = user?.UserId, ["operation"] = operation, ["outcome"] = outcome,
                ["occurredAtUtc"] = audit.OccurredAtUtc });
    }

    public IReadOnlyCollection<CredentialEvidenceAudit> GetAuditTrail() => _audits.Reverse().ToArray();
}
