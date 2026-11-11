using Honeypot.Api.Data.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Honeypot.Api.Data;

public sealed class ReportSnapshotConfiguration : IEntityTypeConfiguration<ReportSnapshotEntity>
{
    public void Configure(EntityTypeBuilder<ReportSnapshotEntity> entity)
    {
        entity.ToTable("report_snapshots");
        entity.HasKey(row => row.Id);
        entity.Property(row => row.Id).HasMaxLength(128);
        entity.Property(row => row.TaskKey).HasMaxLength(256);
        entity.HasIndex(row => row.TaskKey).IsUnique();
        entity.HasIndex(row => new { row.PeriodKind, row.CreatedUnixMs });
    }
}

public sealed class EmailDeliveryConfiguration : IEntityTypeConfiguration<EmailDeliveryEntity>
{
    public void Configure(EntityTypeBuilder<EmailDeliveryEntity> entity)
    {
        entity.ToTable("email_deliveries");
        entity.HasKey(row => row.Id);
        entity.Property(row => row.Id).HasMaxLength(128);
        entity.Property(row => row.Recipient).HasMaxLength(320);
        entity.Property(row => row.RecipientKey).HasMaxLength(320);
        entity.Property(row => row.DeduplicationKey).HasMaxLength(512);
        entity.HasIndex(row => row.DeduplicationKey).IsUnique();
        entity.HasIndex(row => new { row.Status, row.NextAttemptUnixMs });
        entity.HasIndex(row => row.CreatedUnixMs);
        entity.HasOne<ReportSnapshotEntity>().WithMany().HasForeignKey(row => row.ReportSnapshotId).OnDelete(DeleteBehavior.Restrict);
    }
}

public sealed class EmailDeliveryAttemptConfiguration : IEntityTypeConfiguration<EmailDeliveryAttemptEntity>
{
    public void Configure(EntityTypeBuilder<EmailDeliveryAttemptEntity> entity)
    {
        entity.ToTable("email_delivery_attempts");
        entity.HasKey(row => row.Id);
        entity.Property(row => row.Id).HasMaxLength(128);
        entity.HasIndex(row => new { row.DeliveryId, row.Number }).IsUnique();
        entity.HasIndex(row => row.StartedUnixMs);
        entity.HasOne<EmailDeliveryEntity>().WithMany().HasForeignKey(row => row.DeliveryId).OnDelete(DeleteBehavior.Restrict);
    }
}
