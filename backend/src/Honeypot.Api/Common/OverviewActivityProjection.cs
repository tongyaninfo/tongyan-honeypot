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
        var (firstHour, endHour) = HourWindow(now);
        var eventCounts = new int[Hours];
        var activityCounts = new (int Connections, int Failures)[Hours];
        var byAdapter = new Dictionary<string, AdapterCounts>(StringComparer.OrdinalIgnoreCase);

        foreach (var item in events)
        {
            if (item.OccurredAtUtc < firstHour || item.OccurredAtUtc >= endHour) continue;

            var index = (int)(item.OccurredAtUtc - firstHour).TotalHours;
            eventCounts[index]++;
            var connection = IsConnectionAccepted(item);
            var failure = IsAuthenticationFailure(item);
            var violation = IsProtocolViolation(item);
            if (!connection && !failure && !violation) continue;

            // 协议握手步骤仍计入旧趋势，不作为连接或认证失败重复统计。
            if (connection) activityCounts[index].Connections++;
            if (failure) activityCounts[index].Failures++;

            var key = NamedValue(item.AdapterKey);
            if (key is null) continue;
            if (!byAdapter.TryGetValue(key, out var adapter))
            {
                adapter = new AdapterCounts();
                byAdapter.Add(key, adapter);
            }

            if (connection) adapter.AcceptedConnections++;
            if (failure) adapter.AuthenticationFailures++;
            if (violation) adapter.ProtocolViolations++;
            if (item.OccurredAtUtc > adapter.LastActivityAtUtc) adapter.LastActivityAtUtc = item.OccurredAtUtc.ToUniversalTime();

            if (NamedValue(item.SourceIp) is { } source) adapter.SourceIps.Add(source);
        }

        var eventBuckets = new MetricBucket[Hours];
        var activityBuckets = new HourlyActivityMetric[Hours];
        for (var index = 0; index < Hours; index++)
        {
            var key = FormatHour(firstHour.AddHours(index));
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

    public static bool IsConnectionAccepted(InteractionEvent item) =>
        string.Equals(item.EventType, "ConnectionAccepted", StringComparison.OrdinalIgnoreCase);

    public static bool IsAuthenticationFailure(InteractionEvent item) =>
        string.Equals(item.EventType, "AuthenticationAttempted", StringComparison.OrdinalIgnoreCase) &&
        string.Equals(item.Outcome, "failure", StringComparison.OrdinalIgnoreCase);

    internal static bool IsProtocolViolation(InteractionEvent item) =>
        string.Equals(item.EventType, "ProtocolViolation", StringComparison.OrdinalIgnoreCase);

    internal static IEnumerable<InteractionEvent> AdapterEvents(IEnumerable<InteractionEvent> events, DateTimeOffset now, string adapterKey)
    {
        var (start, end) = HourWindow(now);
        return events.Where(item => item.OccurredAtUtc >= start && item.OccurredAtUtc < end &&
            string.Equals(NamedValue(item.AdapterKey), adapterKey, StringComparison.OrdinalIgnoreCase) &&
            (IsConnectionAccepted(item) || IsAuthenticationFailure(item) || IsProtocolViolation(item)));
    }

    internal static string? NamedValue(string? value) => value?.Trim() is { Length: > 0 } trimmed &&
        !trimmed.Equals("unknown", StringComparison.OrdinalIgnoreCase) ? trimmed : null;

    internal static string FormatHour(DateTimeOffset utcHour) =>
        utcHour.ToString("yyyy-MM-ddTHH:00:00Z", CultureInfo.InvariantCulture);

    internal static (DateTimeOffset Start, DateTimeOffset End) HourWindow(DateTimeOffset now)
    {
        var utc = now.UtcDateTime;
        var start = new DateTimeOffset(utc.Date.AddHours(utc.Hour - (Hours - 1)));
        return (start, start.AddHours(Hours));
    }

    public static IEnumerable<InteractionEvent> TodayAuthenticationFailures(IEnumerable<InteractionEvent> events, DateTimeOffset now)
    {
        // 总览和弹层按同一个北京时间自然日统计，包含当天零点，排除次日零点。
        var shanghaiOffset = TimeSpan.FromHours(8);
        var dayStart = new DateTimeOffset(now.ToOffset(shanghaiOffset).Date, shanghaiOffset);
        var nextDayStart = dayStart.AddDays(1);
        return events.Where(item => item.OccurredAtUtc >= dayStart && item.OccurredAtUtc < nextDayStart &&
            IsAuthenticationFailure(item));
    }

    private sealed class AdapterCounts
    {
        public int AcceptedConnections { get; set; }
        public int AuthenticationFailures { get; set; }
        public int ProtocolViolations { get; set; }
        public DateTimeOffset LastActivityAtUtc { get; set; }
        public HashSet<string> SourceIps { get; } = new(StringComparer.OrdinalIgnoreCase);
    }
}
