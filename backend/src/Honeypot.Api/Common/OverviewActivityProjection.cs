using System.Globalization;
using Honeypot.Api.Models;
using Honeypot.Protocol.Abstractions.Models;

namespace Honeypot.Api.Common;

/// <summary>从同一份事件快照汇总总览的协议活动和小时趋势。</summary>
public static class OverviewActivityProjection
{
    private const int Hours = 24;

    public static (MetricBucket[] EventsByHour, AdapterActivityMetric[] AdapterActivity, HourlyActivityMetric[] ActivityByHour)
        Build(IEnumerable<InteractionEvent> events, DateTimeOffset now)
    {
        var utc = now.UtcDateTime;
        var firstHour = new DateTimeOffset(utc.Date.AddHours(utc.Hour - (Hours - 1)));
        var endHour = firstHour.AddHours(Hours);
        var eventCounts = new int[Hours];
        var activityCounts = new (int Connections, int Failures)[Hours];
        var byAdapter = new Dictionary<string, AdapterCounts>(StringComparer.OrdinalIgnoreCase);

        foreach (var item in events)
        {
            if (item.OccurredAtUtc < firstHour || item.OccurredAtUtc >= endHour) continue;

            var index = (int)(item.OccurredAtUtc - firstHour).TotalHours;
            eventCounts[index]++;
            var connection = string.Equals(item.EventType, "ConnectionAccepted", StringComparison.OrdinalIgnoreCase);
            var failure = IsAuthenticationFailure(item);
            var violation = string.Equals(item.EventType, "ProtocolViolation", StringComparison.OrdinalIgnoreCase);
            if (!connection && !failure && !violation) continue;

            // 协议握手步骤仍计入旧趋势，不作为连接或认证失败重复统计。
            if (connection) activityCounts[index].Connections++;
            if (failure) activityCounts[index].Failures++;

            var key = item.AdapterKey?.Trim();
            if (string.IsNullOrEmpty(key) || key.Equals("unknown", StringComparison.OrdinalIgnoreCase)) continue;
            if (!byAdapter.TryGetValue(key, out var adapter))
            {
                adapter = new AdapterCounts();
                byAdapter.Add(key, adapter);
            }

            if (connection) adapter.AcceptedConnections++;
            if (failure) adapter.AuthenticationFailures++;
            if (violation) adapter.ProtocolViolations++;
            if (item.OccurredAtUtc > adapter.LastActivityAtUtc) adapter.LastActivityAtUtc = item.OccurredAtUtc.ToUniversalTime();

            var source = item.SourceIp?.Trim();
            if (!string.IsNullOrEmpty(source) && !source.Equals("unknown", StringComparison.OrdinalIgnoreCase))
                adapter.SourceIps.Add(source);
        }

        var eventBuckets = new MetricBucket[Hours];
        var activityBuckets = new HourlyActivityMetric[Hours];
        for (var index = 0; index < Hours; index++)
        {
            var key = firstHour.AddHours(index).ToString("yyyy-MM-ddTHH:00:00Z", CultureInfo.InvariantCulture);
            eventBuckets[index] = new MetricBucket(key, eventCounts[index]);
            activityBuckets[index] = new HourlyActivityMetric(key, activityCounts[index].Connections, activityCounts[index].Failures);
        }

        var adapterActivity = byAdapter
            .Select(pair => new AdapterActivityMetric(pair.Key.ToLowerInvariant(), pair.Value.AcceptedConnections,
                pair.Value.AuthenticationFailures, pair.Value.SourceIps.Count, pair.Value.ProtocolViolations, pair.Value.LastActivityAtUtc))
            .OrderByDescending(adapter => adapter.AuthenticationFailures)
            .ThenByDescending(adapter => adapter.AcceptedConnections)
            .ThenBy(adapter => adapter.AdapterKey, StringComparer.Ordinal)
            .ToArray();

        return (eventBuckets, adapterActivity, activityBuckets);
    }

    public static bool IsAuthenticationFailure(InteractionEvent item) =>
        string.Equals(item.EventType, "AuthenticationAttempted", StringComparison.OrdinalIgnoreCase) &&
        string.Equals(item.Outcome, "failure", StringComparison.OrdinalIgnoreCase);

    private sealed class AdapterCounts
    {
        public int AcceptedConnections { get; set; }
        public int AuthenticationFailures { get; set; }
        public int ProtocolViolations { get; set; }
        public DateTimeOffset LastActivityAtUtc { get; set; }
        public HashSet<string> SourceIps { get; } = new(StringComparer.OrdinalIgnoreCase);
    }
}
