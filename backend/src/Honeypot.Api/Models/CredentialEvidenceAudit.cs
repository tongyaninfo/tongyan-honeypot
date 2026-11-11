namespace Honeypot.Api.Models;

/// <summary>只记录读取、导出行为及结果，不记录证据内容、密码或会话令牌。</summary>
public sealed record CredentialEvidenceAudit(
    string AuditId, string CredentialArtifactId, string? UserId, DateTimeOffset OccurredAtUtc, string Outcome,
    string Operation = "Read");

public sealed record CredentialEvidenceReadResult(int StatusCode, string Code, CredentialEvidenceView? Evidence);
