namespace Honeypot.Api.Data.Models;

public sealed class CredentialEvidenceEntity
{
    public required string ArtifactId { get; init; }
    public required string ConnectionId { get; init; }
    public required string EventId { get; init; }
    public required string SourceIp { get; init; }
    public required string AdapterKey { get; init; }
    public required string MaterialType { get; init; }
    public long CapturedAtUtcTicks { get; init; }
    public long RetentionUntilUtcTicks { get; init; }
    public required string KeyId { get; init; }
    public int ContentBytes { get; init; }
    public required byte[] Nonce { get; init; }
    public required byte[] Tag { get; init; }
    public required byte[] Ciphertext { get; init; }
    public string? PasswordBookFingerprint { get; set; }
    public string? PasswordBookUsername { get; set; }
    public long? PasswordBookOccurredAtUtcTicks { get; set; }
}

public sealed class CredentialEvidenceAccessAuditEntity
{
    public required string AuditId { get; init; }
    public required string ArtifactId { get; init; }
    public string? UserId { get; init; }
    public long OccurredAtUtcTicks { get; init; }
    public required string Outcome { get; init; }
    public required string Operation { get; init; }
}
