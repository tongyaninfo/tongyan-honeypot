namespace Honeypot.Api.Models;

/// <summary>首页的轻量汇总。原始步骤仅在调查具体连接时读取。</summary>
internal sealed record OverviewEventStatistics(int EventCount, int Accepted, int Attempts, int Failures,
    int TodayFailures, int Violations, int Closed, IReadOnlyCollection<MetricBucket> ByAdapter,
    IReadOnlyCollection<MetricBucket> ByOutcome, IReadOnlyCollection<MetricBucket> ByHour,
    IReadOnlyCollection<AdapterActivityMetric> Adapters, IReadOnlyCollection<HourlyActivityMetric> Activity)
{
    public int? TraceableThreats { get; init; }
    public int ReportOnlyEvents { get; init; }
}
