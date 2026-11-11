using Honeypot.Protocol.Abstractions.Models;

namespace Honeypot.Api.Models;

/// <summary>
/// SignalR 推送及行为查询使用的安全事件视图。这里明确不包含 Password 和认证材料原文，
/// 前端如需取证只能通过受保护的认证证据接口按 artifact id 查询。
/// </summary>
public sealed record RealtimeInteractionEvent(
    string EventId,
    string ConnectionId,
    long Sequence,
    string EventType,
    DateTimeOffset OccurredAtUtc,
    string SourceIp,
    int SourcePort,
    string DestinationIp,
    int DestinationPort,
    string ListenerId,
    string ServiceInstanceId,
    string AdapterKey,
    string Stage,
    string Outcome,
    string? PayloadSummary,
    string? Username,
    int RiskDelta,
    string? CredentialArtifactId,
    bool CredentialCaptured)
{
    public string? Domain { get; init; }
    public string? Database { get; init; }
    public string? AuthenticationMethod { get; init; }
    public string? AuthenticationFailureCode { get; init; }
    public int? AuthenticationAttempt { get; init; }
    public string? MaterialType { get; init; }
    public string? CredentialCaptureStatus { get; init; }
    public string? CloseReason { get; init; }
    /// <summary>行为视图关联的连接步骤数量；实时单事件默认为 1。</summary>
    public int EventCount { get; init; } = 1;

    public static RealtimeInteractionEvent From(InteractionEvent source) => new(
        source.EventId,
        source.ConnectionId,
        source.Sequence,
        source.EventType,
        source.OccurredAtUtc,
        source.SourceIp,
        source.SourcePort,
        source.DestinationIp,
        source.DestinationPort,
        source.ListenerId,
        source.ServiceInstanceId,
        source.AdapterKey,
        source.Stage,
        source.Outcome,
        // 认证事件的摘要可能由适配器拼接了用户名或其它原始字段，实时通道统一不推送。
        !string.IsNullOrWhiteSpace(source.CredentialArtifactId) || !string.IsNullOrEmpty(source.Password)
            ? null
            : source.PayloadSummary,
        source.Username,
        source.RiskDelta,
        source.CredentialArtifactId,
        !string.IsNullOrWhiteSpace(source.CredentialArtifactId))
    {
        Domain = source.Domain,
        Database = source.Database,
        AuthenticationMethod = source.AuthenticationMethod,
        AuthenticationFailureCode = source.AuthenticationFailureCode,
        AuthenticationAttempt = source.AuthenticationAttempt,
        MaterialType = source.MaterialType,
        CredentialCaptureStatus = source.CredentialCaptureStatus,
        CloseReason = source.CloseReason?.ToString(),
    };
}
