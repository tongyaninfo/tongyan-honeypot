namespace Honeypot.Engine.Models;

/// <summary>
/// 按来源 IP 聚合的威胁档案。当前实现只保存进程内状态，持久化由后续 Persistence 项目接管。
/// </summary>
public sealed class ThreatIpProfile
{
    public required string ThreatId { get; init; }
    public required string SourceIp { get; init; }
    public DateTimeOffset FirstSeenUtc { get; set; }
    public DateTimeOffset LastSeenUtc { get; set; }
    public int CurrentScore { get; set; }
    public int MaxScore { get; set; }
    public string ScoreVersion { get; set; } = "v1";
    public string Status { get; set; } = "New";
    public long AttemptCount { get; set; }
    public long SessionCount { get; set; }
    public long ActiveSessionCount { get; set; }
    public long AuthenticationAttemptCount { get; set; }
    public long ProtocolViolationCount { get; set; }
    public HashSet<string> ServicesTouched { get; } = new(StringComparer.OrdinalIgnoreCase);
    public HashSet<int> PortsTouched { get; } = new();
    public string? LastEventId { get; set; }
    public string? LastReason { get; set; }
    public DateTimeOffset? ExpiresAtUtc { get; set; }
}
