using System.ComponentModel.DataAnnotations;

namespace Honeypot.Api.Options;

/// <summary>公网采集可以消耗的事件存储资源。配置在进程启动时校验。</summary>
public sealed class EventStorageOptions
{
    public const string SectionName = "Honeypot:Events";

    [Range(1, 1024)]
    public int QueueCapacity { get; init; } = 256;

    [Range(1, 50_000)]
    public int MemoryEventCapacity { get; init; } = 20_000;

    [Range(1, 168)]
    public int MemoryRetentionHours { get; init; } = 24;

    [Range(1, 366)]
    public int DetailRetentionDays { get; init; } = 30;

    [Range(1, 168)]
    public int HandshakeRetentionHours { get; init; } = 48;

    [Range(1, 366)]
    public int ThreatRetentionDays { get; init; } = 30;

    [Range(1, 366)]
    public int AuditRetentionDays { get; init; } = 90;

    [Range(1, 366)]
    public int ReportRetentionDays { get; init; } = 90;

}
