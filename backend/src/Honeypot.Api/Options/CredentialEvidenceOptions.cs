using System.ComponentModel.DataAnnotations;

namespace Honeypot.Api.Options;

public sealed class CredentialEvidenceOptions
{
    public const string SectionName = "Honeypot:CredentialEvidence";
    public const int DefaultAuditRetentionDays = 90;

    public string? KeyDirectory { get; init; }

    [Range(1, 366)]
    public int AuditRetentionDays { get; init; } = DefaultAuditRetentionDays;

}
