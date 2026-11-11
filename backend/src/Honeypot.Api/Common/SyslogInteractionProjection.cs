using Honeypot.Api.Service;
using Honeypot.Protocol.Abstractions.Models;
using Honeypot.Shared.Models;

namespace Honeypot.Api.Common;

/// <summary>协议观测只投影安全字段；认证失败是 AlwaysFail 的正常结果，风险分不参与日志级别计算。</summary>
public static class SyslogInteractionProjection
{
    public static string AppName(string adapterKey) => adapterKey.ToLowerInvariant() switch
    {
        "ssh" => "honeypot-ssh", "rdp" => "honeypot-rdp", "mysql" => "honeypot-mysql",
        "mssql" => "honeypot-mssql", "mongo" or "mongodb" => "honeypot-mongodb",
        "postgresql" => "honeypot-postgresql", "redis" => "honeypot-redis", "oracle" => "honeypot-oracle",
        "db2" => "honeypot-db2", "memcached" => "honeypot-memcached", "hbase" => "honeypot-hbase",
        "influxdb" => "honeypot-influxdb", "elasticsearch" => "honeypot-elasticsearch",
        "telnet" => "honeypot-telnet", "smb" => "honeypot-smb", "nfs" => "honeypot-nfs",
        _ => "honeypot-events",
    };

    public static SyslogSeverity Severity(InteractionEvent value) => value.EventType.ToLowerInvariant() switch
    {
        "credentialcapturefailed" or "authenticationeventwritefailed" or "storagedegraded" => SyslogSeverity.Error,
        "resourcelimitexceeded" or "capturetruncated" => SyslogSeverity.Warning,
        "authenticationattempted" or "authorizationdenied" or "authenticationrequired" => SyslogSeverity.Notice,
        "bannersent" or "handshakereceived" or "preloginresponsesent" or "tlshandshakecompleted" or
            "sspichallengesent" or "credsspchallengesent" or "x224connectionconfirmsent" or
            "authenticationmethodsrequested" or "handshaketimeout" => SyslogSeverity.Debug,
        "protocolviolation" => string.Equals(value.Outcome, "timeout", StringComparison.OrdinalIgnoreCase)
            ? SyslogSeverity.Debug : SyslogSeverity.Notice,
        "sessionclosed" => value.CloseReason switch
        {
            SessionCloseReason.InternalError or SessionCloseReason.StorageDegraded => SyslogSeverity.Error,
            SessionCloseReason.ResourceLimitExceeded => SyslogSeverity.Warning,
            SessionCloseReason.ProtocolViolation => SyslogSeverity.Notice,
            SessionCloseReason.ClientClosed or SessionCloseReason.HandshakeTimeout or
                SessionCloseReason.IdleTimeout or SessionCloseReason.ListenerStopping => SyslogSeverity.Debug,
            _ => SyslogSeverity.Informational,
        },
        _ => SyslogSeverity.Informational,
    };

    public static IReadOnlyDictionary<string, object?> Fields(InteractionEvent value) => new Dictionary<string, object?>
    {
        ["eventId"] = value.EventId, ["connectionId"] = value.ConnectionId, ["sequence"] = value.Sequence,
        ["occurredAtUtc"] = value.OccurredAtUtc, ["eventType"] = value.EventType, ["outcome"] = value.Outcome,
        ["sourceIp"] = value.SourceIp, ["sourcePort"] = value.SourcePort,
        ["destinationIp"] = value.DestinationIp, ["destinationPort"] = value.DestinationPort,
        ["listenerId"] = value.ListenerId, ["serviceInstanceId"] = value.ServiceInstanceId,
        ["adapterKey"] = value.AdapterKey, ["stage"] = value.Stage,
        ["username"] = value.Username, ["domain"] = value.Domain, ["database"] = value.Database,
        ["authenticationMethod"] = value.AuthenticationMethod,
        ["authenticationFailureCode"] = value.AuthenticationFailureCode,
        ["authenticationAttempt"] = value.AuthenticationAttempt,
        ["materialType"] = value.MaterialType, ["credentialCaptureStatus"] = value.CredentialCaptureStatus,
        ["credentialArtifactId"] = value.CredentialArtifactId, ["riskDelta"] = value.RiskDelta,
        ["closeReason"] = value.CloseReason?.ToString(), ["truncated"] = value.CaptureTruncated,
        // PayloadSummary 和 Password 都可能来自原始输入，禁止整对象序列化或拷贝正文。
    };

    /// <summary>日志外发是旁路；可替换发布器的故障也不得改变取证、访问控制或事件确认结果。</summary>
    public static void PublishSafely(ISyslogPublisher? publisher, string appName, string eventCode,
        SyslogSeverity severity, IReadOnlyDictionary<string, object?> fields)
    {
        if (publisher is null) return;
        try { publisher.Publish(appName, eventCode, severity, fields); }
        catch (Exception) { /* 发布器负责本地健康计数；这里不能递归通过同一故障日志通道报告。 */ }
    }
}
