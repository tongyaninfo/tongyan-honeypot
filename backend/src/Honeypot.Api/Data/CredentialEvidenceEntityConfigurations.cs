using Honeypot.Api.Data.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Honeypot.Api.Data;

public sealed class CredentialEvidenceConfiguration : IEntityTypeConfiguration<CredentialEvidenceEntity>
{
    public void Configure(EntityTypeBuilder<CredentialEvidenceEntity> entity)
    {
        entity.ToTable("credential_evidence");
        entity.HasKey(row => row.ArtifactId);
        entity.Property(row => row.ArtifactId).HasMaxLength(37).UseCollation("NOCASE");
        entity.Property(row => row.ConnectionId).HasMaxLength(128);
        entity.Property(row => row.EventId).HasMaxLength(128).UseCollation("NOCASE");
        entity.Property(row => row.SourceIp).HasMaxLength(64);
        entity.Property(row => row.AdapterKey).HasMaxLength(64);
        entity.Property(row => row.MaterialType).HasMaxLength(64);
        entity.Property(row => row.KeyId).HasMaxLength(64);
        entity.Property(row => row.Nonce).HasMaxLength(12);
        entity.Property(row => row.Tag).HasMaxLength(16);
        entity.Property(row => row.PasswordBookFingerprint).HasMaxLength(64);
        entity.Property(row => row.PasswordBookUsername).HasMaxLength(128);
        entity.HasIndex(row => row.KeyId);
        entity.HasIndex(row => new { row.RetentionUntilUtcTicks, row.ContentBytes });
        entity.HasIndex(row => new { row.CapturedAtUtcTicks, row.ArtifactId });
        entity.HasIndex(row => row.EventId).IsUnique().HasFilter("\"PasswordBookOccurredAtUtcTicks\" IS NOT NULL");
        entity.HasIndex(row => new { row.PasswordBookFingerprint, row.PasswordBookOccurredAtUtcTicks, row.ArtifactId })
            .HasFilter("\"PasswordBookOccurredAtUtcTicks\" IS NOT NULL");
    }
}

public sealed class CredentialEvidenceAccessAuditConfiguration : IEntityTypeConfiguration<CredentialEvidenceAccessAuditEntity>
{
    public void Configure(EntityTypeBuilder<CredentialEvidenceAccessAuditEntity> entity)
    {
        entity.ToTable("credential_evidence_access_audits");
        entity.HasKey(row => row.AuditId);
        entity.Property(row => row.AuditId).HasMaxLength(128);
        entity.Property(row => row.ArtifactId).HasMaxLength(37);
        entity.Property(row => row.UserId).HasMaxLength(128);
        entity.Property(row => row.Outcome).HasMaxLength(32);
        entity.Property(row => row.Operation).HasMaxLength(16);
        // 证据到期后审计按自己的周期保留，不建立级联删除关系。
        entity.HasIndex(row => new { row.OccurredAtUtcTicks, row.AuditId });
    }
}
