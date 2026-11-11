namespace Honeypot.Shared.Models;

/// <summary>已完成白名单投影的日志；主机标识只写入 Syslog 报头。</summary>
public sealed record SyslogRecord(
    DateTimeOffset Timestamp,
    string AppName,
    string EventCode,
    SyslogSeverity Severity,
    string LogId,
    IReadOnlyDictionary<string, object?> Fields);
