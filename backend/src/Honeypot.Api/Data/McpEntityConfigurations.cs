using Honeypot.Api.Data.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Honeypot.Api.Data;

public sealed class McpSettingsConfiguration : IEntityTypeConfiguration<McpSettingsEntity>
{
    public void Configure(EntityTypeBuilder<McpSettingsEntity> entity)
    {
        entity.ToTable("mcp_settings", table =>
        {
            table.HasCheckConstraint("CK_mcp_settings_singleton", "Id = 1");
            table.HasCheckConstraint("CK_mcp_settings_retention", "AuditRetentionDays BETWEEN 1 AND 365");
        });
        entity.HasKey(row => row.Id);
        entity.Property(row => row.Id).ValueGeneratedNever();
        entity.Property(row => row.UpdatedBy).HasMaxLength(128);
        entity.HasData(new McpSettingsEntity
        {
            Id = McpSettingsEntity.SingletonId,
            AuditRetentionDays = McpSettingsEntity.DefaultRetentionDays,
        });
    }
}

public sealed class McpApiKeyConfiguration : IEntityTypeConfiguration<McpApiKeyEntity>
{
    public void Configure(EntityTypeBuilder<McpApiKeyEntity> entity)
    {
        entity.ToTable("mcp_api_keys");
        entity.HasKey(row => row.Id);
        entity.Property(row => row.Id).HasMaxLength(128);
        entity.Property(row => row.Prefix).HasMaxLength(24);
        entity.Property(row => row.SecretDigest).HasMaxLength(32);
        entity.Property(row => row.Name).HasMaxLength(100);
        entity.Property(row => row.Mode).HasMaxLength(16);
        entity.Property(row => row.CreatedBy).HasMaxLength(128);
        entity.HasIndex(row => row.Prefix).IsUnique();
        entity.HasIndex(row => new { row.CreatedUnixMs, row.Id });
    }
}

public sealed class McpCallAuditConfiguration : IEntityTypeConfiguration<McpCallAuditEntity>
{
    public void Configure(EntityTypeBuilder<McpCallAuditEntity> entity)
    {
        entity.ToTable("mcp_call_audits");
        entity.HasKey(row => row.Id);
        entity.Property(row => row.Id).HasMaxLength(128);
        entity.Property(row => row.KeyId).HasMaxLength(128);
        entity.Property(row => row.KeyName).HasMaxLength(100);
        entity.Property(row => row.KeyPrefix).HasMaxLength(24);
        entity.Property(row => row.Tool).HasMaxLength(128);
        entity.Property(row => row.McpMethod).HasMaxLength(128);
        entity.Property(row => row.SourceIp).HasMaxLength(64);
        entity.Property(row => row.HttpMethod).HasMaxLength(16);
        entity.Property(row => row.Result).HasMaxLength(24);
        entity.HasIndex(row => new { row.OccurredUnixMs, row.Id });
        entity.HasIndex(row => new { row.KeyId, row.OccurredUnixMs });
        entity.HasIndex(row => new { row.Tool, row.OccurredUnixMs });
        entity.HasIndex(row => new { row.SourceIp, row.OccurredUnixMs });
        entity.HasIndex(row => new { row.Result, row.OccurredUnixMs });
    }
}
