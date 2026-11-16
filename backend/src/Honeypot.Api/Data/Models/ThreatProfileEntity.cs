using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Honeypot.Api.Data.Models;

/// <summary>每个来源 IP 的当前威胁档案，与产生它的事件同事务保存。</summary>
public sealed class ThreatProfileEntity
{
    public string SourceIp { get; set; } = "";
    public string ThreatId { get; set; } = "";
    public long FirstSeenUtcTicks { get; set; }
    public long LastSeenUtcTicks { get; set; }
    public long ExpiresAtUnixMs { get; set; }
    public int CurrentScore { get; set; }
    public int MaxScore { get; set; }
    public string ScoreVersion { get; set; } = "v1";
    public string Status { get; set; } = "New";
    public long AttemptCount { get; set; }
    public long SessionCount { get; set; }
    public long ActiveSessionCount { get; set; }
    public long AuthenticationAttemptCount { get; set; }
    public long ProtocolViolationCount { get; set; }
    public string ServicesJson { get; set; } = "[]";
    public string PortsJson { get; set; } = "[]";
    public string? LastEventId { get; set; }
    public string? LastReason { get; set; }
}

public sealed class ThreatProfileConfiguration : IEntityTypeConfiguration<ThreatProfileEntity>
{
    public void Configure(EntityTypeBuilder<ThreatProfileEntity> entity)
    {
        entity.ToTable("threat_ip_profiles");
        entity.HasKey(item => item.SourceIp);
        entity.Property(item => item.SourceIp).HasMaxLength(64).UseCollation("NOCASE");
        entity.Property(item => item.ThreatId).HasMaxLength(128);
        entity.Property(item => item.ScoreVersion).HasMaxLength(64);
        entity.Property(item => item.Status).HasMaxLength(32).UseCollation("NOCASE");
        entity.Property(item => item.LastEventId).HasMaxLength(128);
        entity.Property(item => item.LastReason).HasMaxLength(256);
        entity.HasIndex(item => item.ExpiresAtUnixMs);
        entity.HasIndex(item => new { item.LastSeenUtcTicks, item.SourceIp }).IsDescending(true, false);
        entity.HasIndex(item => new { item.CurrentScore, item.LastSeenUtcTicks, item.SourceIp }).IsDescending(true, true, false);
        entity.HasIndex(item => new { item.CurrentScore, item.AuthenticationAttemptCount, item.LastSeenUtcTicks, item.SourceIp })
            .IsDescending(true, true, true, false);
    }
}
