namespace Honeypot.Shared.Models;

/// <summary>自然日/周/月按北京时间解释；custom 使用带时区的半开区间，最长 366 天。</summary>
public sealed record ReportQuery
{
    public string Period { get; init; } = "day";
    public DateTimeOffset? StartAtUtc { get; init; }
    public DateTimeOffset? EndAtUtc { get; init; }
}

public sealed record OperationReport(
    DateTimeOffset GeneratedAtUtc,
    ReportPeriod Period,
    ReportCoverage Coverage,
    ReportTotals Totals,
    ReportComparison Comparison,
    IReadOnlyList<ReportTrendPoint> Trend,
    IReadOnlyList<ReportBreakdown> Protocols,
    IReadOnlyList<ReportBreakdown> Ports,
    IReadOnlyList<ReportBreakdown> Sources,
    IReadOnlyList<ReportBreakdown> Usernames,
    IReadOnlyList<ReportBreakdown> AuthenticationMethods,
    IReadOnlyList<ReportBreakdown> RiskSignals,
    IReadOnlyList<ReportBreakdown> Evidence,
    ReportRuntime Runtime,
    IReadOnlyList<string> Notes)
{
    public IReadOnlyList<ReportBreakdown> Regions { get; init; } = [];
    public ReportMailSummary? MailSummary { get; init; }
}

public sealed record ReportPeriod(string Kind, string TimeZone, DateTimeOffset StartAtUtc,
    DateTimeOffset EndAtUtc, string Granularity, bool IsCurrentPeriod);

/// <summary>complete/partial/unknown 指采集心跳覆盖；未覆盖时段不可解释为零事件。</summary>
public sealed record ReportCoverage(string Status, double CoveredSeconds, double UnknownSeconds,
    double CoveragePercent, DateTimeOffset? FirstSampleAtUtc, DateTimeOffset? LastSampleAtUtc,
    long PersistenceFailures, bool HasObservedEvents);

/// <summary>null 表示没有可用观测，不等同于零；有部分覆盖时数值仅代表已记录的数据。</summary>
public sealed record ReportTotals(long? EventCount, long? AcceptedConnections, long? UniqueSourceIps,
    long? NewSourceIps, long? AuthenticationAttempts, long? AuthenticationFailures,
    long? ProtocolViolations, long? EvidenceCount, long? TruncatedEvents, long? SessionClosed = null);

public sealed record ReportComparison(DateTimeOffset StartAtUtc, DateTimeOffset EndAtUtc,
    string CoverageStatus, ReportTotals Totals, double? ConnectionChangePercent,
    double? SourceIpChangePercent, double? AuthenticationFailureChangePercent);

public sealed record ReportTrendPoint(DateTimeOffset StartAtUtc, long? Events, long? Connections,
    long? AuthenticationFailures, long? ProtocolViolations, string CoverageStatus = "unknown");

/// <summary>每项为当前区间内已记录事件聚合；排行前 10，风险仅为事件风险增量分段。</summary>
public sealed record ReportBreakdown(string Key, long Events, long Connections,
    long AuthenticationFailures, long SourceIps);

/// <summary>CPU 是进程占整机逻辑处理器总算力的百分比，内存为进程工作集，均非宿主总占用。</summary>
public sealed record ReportRuntime(long SampleCount, double? AverageProcessCpuPercent,
    double? PeakProcessCpuPercent, long? AverageProcessMemoryBytes, long? PeakProcessMemoryBytes,
    long? PeakActiveConnections, double? AverageRunningListeners, long? PeakFailedListeners,
    long? LastConfiguredListeners, double? AllListenersRunningPercent,
    DateTimeOffset? LastSampleAtUtc, long? LastDataDiskFreeBytes = null, long? MinimumDataDiskFreeBytes = null);

public sealed record ReportMailSummary(long Accepted, long Failed, long Pending, long Retrying, long Unknown = 0, long Sending = 0);
