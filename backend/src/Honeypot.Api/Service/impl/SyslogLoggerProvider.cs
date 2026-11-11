using Honeypot.Shared.Models;
using Honeypot.Api.Workers;

namespace Honeypot.Api.Service.impl;

/// <summary>框架日志只投影安全元数据。格式化后的正文、异常正文及作用域可能含令牌。</summary>
[ProviderAlias("Syslog")]
public sealed class SyslogLoggerProvider(ISyslogPublisher publisher) : ILoggerProvider
{
    public ILogger CreateLogger(string categoryName) => new Logger(publisher, categoryName);
    public void Dispose() { }

    private sealed class Logger(ISyslogPublisher publisher, string category) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel level) => level != LogLevel.None &&
            category is not (SyslogDeliveryWorker.LoggerCategory or "Honeypot.Syslog.LocalAudit");

        public void Log<TState>(LogLevel level, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            if (!IsEnabled(level)) return;
            var fields = new Dictionary<string, object?>
            {
                ["category"] = category, ["originalLevel"] = level.ToString(),
                ["eventNumber"] = eventId.Id, ["exceptionType"] = exception?.GetType().Name
            };
            if (state is IEnumerable<KeyValuePair<string, object?>> values && category.StartsWith("Honeypot.", StringComparison.Ordinal))
            {
                foreach (var (key, value) in values)
                {
                    if (key is "InstanceId" or "ListenerId" or "ConnectionId" or "FailureCount" or "EventId" or "ErrorCode" or "ExceptionType")
                        fields[char.ToLowerInvariant(key[0]) + key[1..]] = value;
                }
            }
            publisher.Publish(AppName(category), eventId.Name ?? "LOGGER_EVENT", level switch
            {
                LogLevel.Critical => SyslogSeverity.Critical,
                LogLevel.Error => SyslogSeverity.Error,
                LogLevel.Warning => SyslogSeverity.Warning,
                LogLevel.Information => SyslogSeverity.Informational,
                _ => SyslogSeverity.Debug
            }, fields);
        }

        private static string AppName(string name)
        {
            if (name.StartsWith("Microsoft.EntityFrameworkCore", StringComparison.Ordinal) || name.Contains("DbInitializer", StringComparison.Ordinal))
                return "honeypot-storage";
            if (name.Contains("SignalR", StringComparison.Ordinal) || name.Contains("Realtime", StringComparison.Ordinal))
                return "honeypot-realtime";
            if (name.Contains("TcpListener", StringComparison.Ordinal) || name.Contains("ServiceInstanceRecovery", StringComparison.Ordinal))
                return "honeypot-runtime";
            if (name.Contains("IPLocation", StringComparison.Ordinal)) return "honeypot-iplocation";
            if (name.Contains("ReportInteractionEventStore", StringComparison.Ordinal)) return "honeypot-events";
            if (name.Contains("Report", StringComparison.Ordinal)) return "honeypot-report";
            if (name.Contains("Notification", StringComparison.Ordinal) || name.Contains("Mail", StringComparison.Ordinal)) return "honeypot-mail";
            if (name.StartsWith("Microsoft.Hosting", StringComparison.Ordinal)) return "honeypot-host";
            return "honeypot-api";
        }
    }
}
