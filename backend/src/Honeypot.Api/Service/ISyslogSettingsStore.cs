using Honeypot.Shared.Models;

namespace Honeypot.Api.Service;

public interface ISyslogSettingsStore
{
    SyslogSettingsSnapshot Current { get; }
    /// <summary>发送链路的只读内部快照，调用方不得修改其中数组；避免每条日志复制配置。</summary>
    SyslogSettingsSnapshot DeliverySnapshot => Current;
    event Action<SyslogSettingsSnapshot>? Changed;
    Task<SyslogSettingsSnapshot> SaveAsync(SyslogSettings settings, long expectedRevision, CancellationToken cancellationToken = default);
}

public sealed class SyslogSettingsConflictException : Exception { }
public sealed class SyslogSettingsUnavailableException : Exception { }
