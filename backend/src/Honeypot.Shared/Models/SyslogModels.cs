using System.Text.Json.Serialization;

namespace Honeypot.Shared.Models;

/// <summary>传输协议独立于消息严重级别；RELP 为带应答的 TCP 协议。</summary>
[JsonConverter(typeof(JsonStringEnumConverter<SyslogProtocol>))]
public enum SyslogProtocol { Udp, Tcp, Tls, Relp }

/// <summary>RFC 5424 严重级别，数值越小越严重；不能与 .NET LogLevel 直接强转。</summary>
public enum SyslogSeverity { Emergency = 0, Alert, Critical, Error, Warning, Notice, Informational, Debug }

/// <summary>保留旧配置字段的读取兼容。转发始终使用 local0 和全部严重级别。</summary>
public sealed record SyslogTarget(string Id, string Name, string Host, int Port, SyslogProtocol Protocol,
    bool Enabled = true, bool IgnoreSslErrors = false, int[]? IgnoredSeverities = null, int Facility = SyslogTarget.DefaultFacility)
{
    public const int DefaultFacility = 16;
}

/// <summary>不包含主机名和凭据；主机名由服务端从当前计算机确定。</summary>
public sealed record SyslogSettings
{
    public bool Enabled { get; init; }
    public SyslogTarget[] Targets { get; init; } = [];
    public int ConnectTimeoutSeconds { get; init; } = 10;
    public int WriteTimeoutSeconds { get; init; } = 10;
    public int QueueCapacity { get; init; } = 10000;
    public long SpoolMaxBytes { get; init; } = 268435456;
    public int RetentionHours { get; init; } = 24;
}

public sealed record SyslogSettingsSnapshot(SyslogSettings Settings, long Revision, string Hostname, string? ConfigFault = null);
public sealed record UpdateSyslogSettingsRequest(SyslogSettings Settings, long ExpectedRevision);
public sealed record SyslogTestRequest(string TargetId, string? Message = null)
{
    public const int MaximumMessageLength = 256;
}
public sealed record SyslogTargetStatus(string TargetId, string State, long PendingCount, long SentCount,
    long ConfirmedCount, long FailedCount, long RetriedCount, long DroppedCount, long TruncatedCount,
    DateTimeOffset? LastSentAtUtc = null, DateTimeOffset? LastConfirmedAtUtc = null, string? LastErrorCode = null);
public sealed record SyslogDeliveryStatus(bool Enabled, string Hostname, IReadOnlyList<SyslogTargetStatus> Targets, string? ConfigFault = null,
    long PausedPendingCount = 0, long DiscardedPausedCount = 0);
/// <summary>Stage 区分本地提交、流写入和 RELP 应答，不承诺接收端已持久化。</summary>
public sealed record SyslogTestResult(string TargetId, string CorrelationId, bool Succeeded, string Stage,
    string? ErrorCode = null, DateTimeOffset? CompletedAtUtc = null);
/// <summary>浏览器只能提交固定事件码和页面键，不接收消息正文、堆栈、URL 或客户端级别。</summary>
public sealed record FrontendDiagnosticRequest(string EventCode, string RouteKey, int? HttpStatus = null, int Count = 1);
