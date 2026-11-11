using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Honeypot.Api.Data.Models;

/// <summary>单机每 30 秒采样。覆盖只认连续成功采样之间的区间，停机/写入失败不补成在线。</summary>
public sealed class ReportRuntimeSampleEntity
{
    public long CapturedAtUnixMs { get; set; }
    public long CoverageStartAtUnixMs { get; set; }
    public double? ProcessCpuPercent { get; set; }
    public long ProcessMemoryBytes { get; set; }
    public long? DataDiskFreeBytes { get; set; }
    public long ActiveConnections { get; set; }
    public int ConfiguredListeners { get; set; }
    public int RunningListeners { get; set; }
    public int FailedListeners { get; set; }
    public long PersistenceFailures { get; set; }
}

public sealed class ReportRuntimeSampleConfiguration : IEntityTypeConfiguration<ReportRuntimeSampleEntity>
{
    public void Configure(EntityTypeBuilder<ReportRuntimeSampleEntity> entity)
    {
        entity.ToTable("report_runtime_samples");
        entity.HasKey(item => item.CapturedAtUnixMs);
        entity.Property(item => item.CapturedAtUnixMs).ValueGeneratedNever();
        entity.HasIndex(item => item.CoverageStartAtUnixMs);
    }
}
