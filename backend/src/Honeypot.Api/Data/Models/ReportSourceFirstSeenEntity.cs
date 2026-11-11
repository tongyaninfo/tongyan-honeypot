using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Honeypot.Api.Data.Models;

/// <summary>保留跨报告周期的首次观测时间；事件乱序到达时取较早值。</summary>
public sealed class ReportSourceFirstSeenEntity
{
    public string SourceIp { get; set; } = "";
    public long FirstSeenAtUnixMs { get; set; }
}

public sealed class ReportSourceFirstSeenConfiguration : IEntityTypeConfiguration<ReportSourceFirstSeenEntity>
{
    public void Configure(EntityTypeBuilder<ReportSourceFirstSeenEntity> entity)
    {
        entity.ToTable("report_source_first_seen");
        entity.HasKey(item => item.SourceIp);
        entity.Property(item => item.SourceIp).HasMaxLength(64);
        entity.HasIndex(item => item.FirstSeenAtUnixMs);
    }
}
