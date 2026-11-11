namespace Honeypot.Api.Models;

/// <summary>
/// 管理台运行总览使用的聚合指标。运行数据来自当前进程内事件和监听器状态。
/// </summary>
public sealed record OverviewMetrics
{
    public required DateTimeOffset GeneratedAtUtc { get; init; }
    public required int EventCount { get; init; }
    public required int AcceptedConnections { get; init; }
    public required int AuthenticationAttempts { get; init; }
    public required int AuthenticationFailures { get; init; }
    public int TodayAuthenticationFailures { get; init; }
    public required int ProtocolViolations { get; init; }
    public required int SessionClosed { get; init; }
    public required int ThreatIpCount { get; init; }
    public required int ServiceInstanceCount { get; init; }
    public required int ListenerCount { get; init; }
    public required int RunningListenerCount { get; init; }
    public required int FailedListenerCount { get; init; }
    public required int ActiveConnections { get; init; }
    public required long AcceptedCount { get; init; }
    public required long ListenerErrorCount { get; init; }
    public required IReadOnlyCollection<MetricBucket> EventsByAdapter { get; init; }
    public required IReadOnlyCollection<MetricBucket> EventsByOutcome { get; init; }
    public required IReadOnlyCollection<MetricBucket> EventsByHour { get; init; }
    public IReadOnlyCollection<AdapterActivityMetric> AdapterActivity { get; init; } = [];
    public IReadOnlyCollection<HourlyActivityMetric> ActivityByHour { get; init; } = [];
    public required IReadOnlyCollection<ListenerOverview> Listeners { get; init; }
    public HostOverview? Host { get; init; }
}

public sealed record HostOverview(
    string OsVersion,
    string HostName,
    IReadOnlyList<string> IpAddresses,
    DateTimeOffset? BootTimeUtc);

public sealed record MetricBucket(string Key, long Count);

public sealed record AdapterActivityMetric(
    string AdapterKey,
    int AcceptedConnections,
    int AuthenticationFailures,
    int SourceIpCount,
    int ProtocolViolations,
    DateTimeOffset LastActivityAtUtc);

public sealed record HourlyActivityMetric(string Key, int AcceptedConnections, int AuthenticationFailures);

public sealed record ListenerOverview(
    string ListenerId,
    string InstanceId,
    string AdapterKey,
    int Port,
    string State,
    int ActiveConnections,
    long AcceptedCount,
    long ErrorCount);
