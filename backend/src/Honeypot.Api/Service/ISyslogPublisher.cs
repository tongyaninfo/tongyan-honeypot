using Honeypot.Shared.Models;

namespace Honeypot.Api.Service;

/// <summary>提交已经过业务字段筛选的日志，调用方不等待网络或磁盘。</summary>
public interface ISyslogPublisher
{
    void Publish(string appName, string eventCode, SyslogSeverity severity, IReadOnlyDictionary<string, object?>? fields = null);
}
