using Honeypot.Api.Data.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Honeypot.Api.Data;

public sealed class ManagementOperationAuditConfiguration : IEntityTypeConfiguration<ManagementOperationAuditEntity>
{
    public void Configure(EntityTypeBuilder<ManagementOperationAuditEntity> entity)
    {
        entity.ToTable("management_operation_audits");
        entity.HasKey(row => row.Id);
        entity.Property(row => row.Id).HasMaxLength(128);
        entity.Property(row => row.Operation).HasMaxLength(48);
        entity.Property(row => row.ActorUserId).HasMaxLength(128);
        entity.Property(row => row.ResourceId).HasMaxLength(128);
        entity.HasIndex(row => new { row.OccurredAtUnixMs, row.Id });
    }
}
