using Honeypot.Api.Models;
using Honeypot.Api.Service;
using Honeypot.Api.Service.impl;
using Honeypot.Engine.Service;
using Honeypot.Protocol.Abstractions.Service;

namespace Honeypot.Api.Common;

/// <summary>REST 管理台和 MCP 共用运行指标口径；调用方可省略宿主身份信息。</summary>
public static class OverviewMetricsReader
{
    public static OverviewMetrics Read(IInteractionEventStore events, IThreatProfileStore threats,
        IListenerHost listenerHost, IServiceInstanceStore instances, DateTimeOffset now, bool includeHost,
        bool includeActivityCoverage = false, CancellationToken cancellationToken = default)
    {
        var stats = Statistics(events, now, includeActivityCoverage, cancellationToken);
        var listeners = listenerHost.GetStatuses();
        var instanceById = instances.GetAll()
            .ToDictionary(item => item.InstanceId, StringComparer.OrdinalIgnoreCase);


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
            EventCount = stats.EventCount, ReportOnlyEvents = stats.ReportOnlyEvents, AcceptedConnections = stats.Accepted, AuthenticationAttempts = stats.Attempts,
            AuthenticationFailures = stats.Failures, TodayAuthenticationFailures = stats.TodayFailures,
            ProtocolViolations = stats.Violations, SessionClosed = stats.Closed,
            ThreatIpCount = threats.Count(), TraceableThreatIpCount = stats.TraceableThreats,
            ServiceInstanceCount = instanceById.Count,
            ListenerCount = listeners.Count,
            RunningListenerCount = listeners.Count(item => item.State.Equals("Running", StringComparison.OrdinalIgnoreCase)),
            FailedListenerCount = listeners.Count(item => item.State.Equals("Failed", StringComparison.OrdinalIgnoreCase)),
            ActiveConnections = listeners.Sum(item => item.ActiveConnections),
            AcceptedCount = listeners.Sum(item => item.AcceptedCount),
            ListenerErrorCount = listeners.Sum(item => item.ErrorCount),
            EventsByAdapter = stats.ByAdapter, EventsByOutcome = stats.ByOutcome, EventsByHour = stats.ByHour,
            AdapterActivity = stats.Adapters, ActivityByHour = stats.Activity,
            Listeners = listenerOverview,
            Host = includeHost ? HostOverviewReader.Read(now) : null,
        };
        return metrics;
    }

    internal static OverviewEventStatistics Statistics(IInteractionEventStore events, DateTimeOffset now,
        bool includeActivityCoverage = false, CancellationToken cancellationToken = default)
    {
        if (events is ReportInteractionEventStore persistent) return persistent.ReadOverviewStatistics(now, includeActivityCoverage, cancellationToken);
        // 内存实现仅用于隔离环境；与持久化版本使用相同的 24 小时统计口径。
        var items = events.GetAll().Where(item => item.OccurredAtUtc >= now.AddHours(-24) && item.OccurredAtUtc <= now).ToArray();
        var (hours, adapters, activity) = OverviewActivityProjection.Build(items, now);
        MetricBucket[] Buckets(Func<Honeypot.Protocol.Abstractions.Models.InteractionEvent, string?> key) =>
            items.GroupBy(item => OverviewActivityProjection.NamedValue(key(item)) ?? "unknown", StringComparer.OrdinalIgnoreCase)
                .Select(group => new MetricBucket(group.Key, group.LongCount())).OrderByDescending(row => row.Count).ToArray();
        return new(items.Length, items.Count(OverviewActivityProjection.IsConnectionAccepted),
            items.Count(item => item.EventType.Equals("AuthenticationAttempted", StringComparison.OrdinalIgnoreCase)),
            items.Count(OverviewActivityProjection.IsAuthenticationFailure), OverviewActivityProjection.TodayAuthenticationFailures(items, now).Count(),
            items.Count(OverviewActivityProjection.IsProtocolViolation), items.Count(item => item.EventType.Equals("SessionClosed", StringComparison.OrdinalIgnoreCase)),
            Buckets(item => item.AdapterKey), Buckets(item => item.Outcome), hours, adapters, activity);
    }
}
