namespace Honeypot.Protocol.Abstractions.Models;

/// <summary>
/// 不可变交互事件。ConnectionAccepted 必须在协议适配器开始处理前写入。
/// </summary>
public sealed record InteractionEvent
{
    public required string EventId { get; init; }
    public required string ConnectionId { get; init; }
    public long Sequence { get; init; }
    public required string EventType { get; init; }
    public DateTimeOffset OccurredAtUtc { get; init; }
    public required string SourceIp { get; init; }
    public int SourcePort { get; init; }
    public required string DestinationIp { get; init; }
    public int DestinationPort { get; init; }
    public string Transport { get; init; } = "tcp";
    public required string ListenerId { get; init; }
    public required string ServiceInstanceId { get; init; }
    public required string AdapterKey { get; init; }
    public required string ProfileId { get; init; }
    public string Stage { get; init; } = "accepted";
    public string Outcome { get; init; } = "recorded";
    public string? PayloadSummary { get; init; }
    public string? Username { get; init; }
    // 保留旧代码的源兼容性，但永不通过 HTTP/SignalR 序列化密码。
    [System.Text.Json.Serialization.JsonIgnore]
    public string? Password { get; init; }
    public string? Domain { get; init; }
    public string? Database { get; init; }
    public string? AuthenticationMethod { get; init; }
    public string? AuthenticationFailureCode { get; init; }
    public int? AuthenticationAttempt { get; init; }
    public string? MaterialType { get; init; }
    public string? CredentialCaptureStatus { get; init; }
    public bool CaptureTruncated { get; init; }
    public int RiskDelta { get; init; }
    public string? RuleVersion { get; init; }
    public string? CredentialArtifactId { get; init; }
    /// <summary>只在会话最终关闭事件中使用，避免把存储失败或超时误报为正常完成。</summary>
    public SessionCloseReason? CloseReason { get; init; }
}
