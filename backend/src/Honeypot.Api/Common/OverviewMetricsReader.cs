using Honeypot.Api.Models;
using Honeypot.Api.Service;
using Honeypot.Engine.Service;
using Honeypot.Protocol.Abstractions.Service;

namespace Honeypot.Api.Common;

/// <summary>REST 管理台和 MCP 共用运行指标口径；调用方可省略宿主身份信息。</summary>
public static class OverviewMetricsReader
{
    public static OverviewMetrics Read(IInteractionEventStore events, IThreatProfileStore threats,
        IListenerHost listenerHost, IServiceInstanceStore instances, DateTimeOffset now, bool includeHost)
    {
        // 总览和导出默认以 Asia/Shanghai 展示，今日统计按同一自然日计算。
        var shanghaiOffset = TimeSpan.FromHours(8);
        var dayStart = new DateTimeOffset(now.ToOffset(shanghaiOffset).Date, shanghaiOffset);
        var nextDayStart = dayStart.AddDays(1);
        var allEvents = events.GetAll();
        var authenticationFailures = allEvents.Where(OverviewActivityProjection.IsAuthenticationFailure);
        var listeners = listenerHost.GetStatuses();
        var instanceById = instances.GetAll()
            .ToDictionary(item => item.InstanceId, StringComparer.OrdinalIgnoreCase);
        var (eventBuckets, adapterActivity, activityByHour) = OverviewActivityProjection.Build(allEvents, now);

        var listenerOverview = listeners
            .Select(listener => new ListenerOverview(
                listener.ListenerId,
                listener.InstanceId,
                instanceById.TryGetValue(listener.InstanceId, out var instance) ? instance.AdapterKey : string.Empty,
                listener.Port,
                listener.State,
                listener.ActiveConnections,
                listener.AcceptedCount,
                listener.ErrorCount))
            .ToArray();

        var metrics = new OverviewMetrics
        {
            GeneratedAtUtc = now,
            EventCount = allEvents.Count,
            AcceptedConnections = allEvents.Count(item => item.EventType.Equals("ConnectionAccepted", StringComparison.OrdinalIgnoreCase)),
            AuthenticationAttempts = allEvents.Count(item => item.EventType.Equals("AuthenticationAttempted", StringComparison.OrdinalIgnoreCase)),
            AuthenticationFailures = authenticationFailures.Count(),
            TodayAuthenticationFailures = authenticationFailures.Count(item => item.OccurredAtUtc >= dayStart && item.OccurredAtUtc < nextDayStart),
            ProtocolViolations = allEvents.Count(item => item.EventType.Equals("ProtocolViolation", StringComparison.OrdinalIgnoreCase)),
            SessionClosed = allEvents.Count(item => item.EventType.Equals("SessionClosed", StringComparison.OrdinalIgnoreCase)),
            ThreatIpCount = threats.GetAll().Count,
            ServiceInstanceCount = instances.GetAll().Count,
            ListenerCount = listeners.Count,
            RunningListenerCount = listeners.Count(item => item.State.Equals("Running", StringComparison.OrdinalIgnoreCase)),
            FailedListenerCount = listeners.Count(item => item.State.Equals("Failed", StringComparison.OrdinalIgnoreCase)),
            ActiveConnections = listeners.Sum(item => item.ActiveConnections),
            AcceptedCount = listeners.Sum(item => item.AcceptedCount),
            ListenerErrorCount = listeners.Sum(item => item.ErrorCount),
            EventsByAdapter = allEvents
                .GroupBy(item => string.IsNullOrWhiteSpace(item.AdapterKey) ? "unknown" : item.AdapterKey, StringComparer.OrdinalIgnoreCase)
                .Select(group => new MetricBucket(group.Key, group.LongCount()))
                .OrderByDescending(item => item.Count)
                .ToArray(),
            EventsByOutcome = allEvents
                .GroupBy(item => string.IsNullOrWhiteSpace(item.Outcome) ? "unknown" : item.Outcome, StringComparer.OrdinalIgnoreCase)
                .Select(group => new MetricBucket(group.Key, group.LongCount()))
                .OrderByDescending(item => item.Count)
                .ToArray(),
            EventsByHour = eventBuckets,
            AdapterActivity = adapterActivity,
            ActivityByHour = activityByHour,
            Listeners = listenerOverview,
            Host = includeHost ? HostOverviewReader.Read(now) : null,
        };
        return metrics;
    }
}
