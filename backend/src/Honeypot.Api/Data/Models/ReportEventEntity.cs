using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Honeypot.Api.Data.Models;

/// <summary>报表白名单事实，不保存 Password、PayloadSummary、票据或其他原始认证材料。</summary>
public sealed class ReportEventEntity
{
    public string EventId { get; set; } = "";
    public long OccurredAtUnixMs { get; set; }
    public string EventType { get; set; } = "";
    public string SourceIp { get; set; } = "";
    public string AdapterKey { get; set; } = "";
    public int DestinationPort { get; set; }
    public string Username { get; set; } = "";
    public string AuthenticationMethod { get; set; } = "";
    public bool IsAuthenticationFailure { get; set; }
    public string RiskSignal { get; set; } = "none";
    public string EvidenceKind { get; set; } = "none";
    public string? CredentialArtifactId { get; set; }
    public bool CaptureTruncated { get; set; }
}

public sealed class ReportEventConfiguration : IEntityTypeConfiguration<ReportEventEntity>
{
    public void Configure(EntityTypeBuilder<ReportEventEntity> entity)
    {
        entity.ToTable("report_events");
        entity.HasKey(item => item.EventId);
        entity.Property(item => item.EventId).HasMaxLength(128).UseCollation("NOCASE");
        entity.Property(item => item.EventType).HasMaxLength(64);
        entity.Property(item => item.SourceIp).HasMaxLength(64);
        entity.Property(item => item.AdapterKey).HasMaxLength(64);
        entity.Property(item => item.Username).HasMaxLength(128);
        entity.Property(item => item.AuthenticationMethod).HasMaxLength(64);
        entity.Property(item => item.RiskSignal).HasMaxLength(16);
        entity.Property(item => item.EvidenceKind).HasMaxLength(64);
        entity.Property(item => item.CredentialArtifactId).HasMaxLength(128);
        entity.HasIndex(item => item.OccurredAtUnixMs);
        entity.HasIndex(item => new { item.SourceIp, item.OccurredAtUnixMs });
        entity.HasIndex(item => new { item.EventType, item.OccurredAtUnixMs });
    }
}
