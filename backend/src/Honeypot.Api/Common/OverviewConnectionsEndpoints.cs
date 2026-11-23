using Honeypot.Api.Models;
using Honeypot.Api.Service;
using Honeypot.Api.Service.impl;
using Honeypot.Engine.Service;
using Honeypot.Protocol.Abstractions.Models;
using Honeypot.Protocol.Abstractions.Service;
using Honeypot.Shared.Models;

namespace Honeypot.Api.Common;

public static class OverviewConnectionsEndpoints
{
    public static void MapOverviewMetricsEndpoint(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/api/v1/metrics/overview", async (IInteractionEventStore events, IThreatProfileStore threats,
            IListenerHost listeners, IServiceInstanceStore instances, ReportIngestionHealth ingestion,
            SqliteReportService reports, OverviewActiveConnections active, CancellationToken ct) =>
        {
            var snapshot = active.Capture();
            var metrics = OverviewMetricsReader.Read(events, threats, listeners, instances, snapshot.AsOfUtc, includeHost: true,
                includeActivityCoverage: true, cancellationToken: ct);
            var activity = events is ReportInteractionEventStore ? metrics.ActivityByHour
                : await reports.ReadOverviewActivityAsync(snapshot.AsOfUtc, ct);
            return Results.Ok(ApiResult<OverviewMetrics>.Ok(metrics with
            {
                ActivityByHour = activity,
                ActiveConnections = snapshot.Items.Count,
                EventStorage = EventStorageMetrics.From(ingestion),
            }));
        });
    }

    public static void MapOverviewConnectionsEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/api/v1/metrics/overview/connections", (
            string? scope, string? adapterKey, string? metric, int? page, int? pageSize, DateTimeOffset? asOfUtc,
            IListenerHost listeners, IInteractionEventStore events,
            IThreatProfileStore threats, OverviewActiveConnections snapshots, TimeProvider clock, HttpContext context) =>
        {
            context.Response.Headers.CacheControl = "no-store";
            var current = clock.GetUtcNow();
            var now = asOfUtc is { } cutoff && cutoff <= current ? cutoff : current;
            if (scope == "active")
            {
                var active = asOfUtc is { } asOf ? snapshots.Find(asOf)?.Items : listeners.GetActiveConnections();
                if (active is null)
                    return Results.Json(ApiResult<object>.Fail("OVERVIEW_SNAPSHOT_EXPIRED", "活动连接快照已过期，请刷新首页。"),
                        statusCode: StatusCodes.Status410Gone);
                return Paged(active.Select(connection => new OverviewConnectionRow(connection.ConnectionId,
                    connection.ConnectionId, connection.AcceptedAtUtc, connection.SourceIp, connection.SourcePort,
                    connection.AdapterKey, connection.DestinationPort)), false, page, pageSize);
            }
            if (scope == "adapterActivity")
                return ReadAdapterActivity(events, now, adapterKey, metric, page, pageSize);
            if (events is ReportInteractionEventStore persistent && scope is "accepted" or "authenticationFailures" or "threatConnections")
                return Results.Ok(ApiResult<object>.Ok(persistent.ReadOverviewPage(scope, null, null, now, page, pageSize)));
            IEnumerable<OverviewConnectionRow>? rows = scope switch
            {
                "accepted" => events.GetAll().Where(OverviewActivityProjection.IsConnectionAccepted).Select(FromEvent),
                "authenticationFailures" => OverviewActivityProjection.TodayAuthenticationFailures(events.GetAll(), now).Select(FromAuthenticationFailure),
                "threatConnections" => ThreatConnections(events, threats),
                _ => null,
            };
            if (rows is null)
                return Results.BadRequest(ApiResult<object>.Fail("INVALID_SCOPE", "连接范围必须是 active、accepted、authenticationFailures、threatConnections 或 adapterActivity。"));

            return Paged(rows, scope == "threatConnections", page, pageSize);
        });
    }

    private static IResult ReadAdapterActivity(IInteractionEventStore events, DateTimeOffset now, string? adapterKey, string? metric,
        int? page, int? pageSize)
    {
        if (OverviewActivityProjection.NamedValue(adapterKey) is not { Length: <= 64 } adapter)
            return Results.BadRequest(ApiResult<object>.Fail("INVALID_ADAPTER_KEY", "请提供有效的协议标识。"));
        if (metric is not ("acceptedConnections" or "authenticationFailures" or "sourceIpCount" or "protocolViolations"))
            return Results.BadRequest(ApiResult<object>.Fail("INVALID_ACTIVITY_METRIC", "请提供有效的协议活动指标。"));

        if (events is ReportInteractionEventStore persistent)
            return Results.Ok(ApiResult<object>.Ok(persistent.ReadOverviewPage("adapterActivity", adapter, metric, now, page, pageSize)));
        var activity = OverviewActivityProjection.AdapterEvents(events.GetAll(), now, adapter);
        var rows = metric switch
        {
            "acceptedConnections" => activity.Where(OverviewActivityProjection.IsConnectionAccepted).Select(FromEvent),
            "authenticationFailures" => activity.Where(OverviewActivityProjection.IsAuthenticationFailure).Select(FromAuthenticationFailure),
            "protocolViolations" => activity.Where(OverviewActivityProjection.IsProtocolViolation)
                .Select(item => FromEvent(item) with { ProtocolViolationSummary = item.PayloadSummary }),
            _ => activity.Where(item => OverviewActivityProjection.NamedValue(item.SourceIp) is not null)
                .Select(item => FromEvent(item) with { SourceIp = item.SourceIp.Trim(), EventType = item.EventType }),
        };
        return Paged(rows, metric == "sourceIpCount", page, pageSize);
    }

    private static IResult Paged(IEnumerable<OverviewConnectionRow> rows, bool distinctSources, int? page, int? pageSize)
    {
        IEnumerable<OverviewConnectionRow> ordered = rows.OrderByDescending(row => row.OccurredAtUtc).ThenBy(row => row.Id, StringComparer.Ordinal);
        // 来源指标在分页前去重，每个来源保留同一范围内最近的一条记录。
        if (distinctSources)
            ordered = ordered.GroupBy(row => row.SourceIp, StringComparer.OrdinalIgnoreCase).Select(group => group.First());
        return Results.Ok(ApiResult<object>.Ok(QueryPage.Create(ordered, page, pageSize)));
    }

    private static IEnumerable<OverviewConnectionRow> ThreatConnections(IInteractionEventStore events, IThreatProfileStore threats)
    {
        var accepted = events.GetAll().Where(OverviewActivityProjection.IsConnectionAccepted).ToArray();
        var candidates = accepted.Select(item => item.SourceIp).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var sources = threats.GetObservedSources(candidates);
        return accepted.Where(item => sources.Contains(item.SourceIp)).Select(FromEvent);
    }

    private static OverviewConnectionRow FromEvent(InteractionEvent item) => new(
        item.EventId, item.ConnectionId, item.OccurredAtUtc.ToUniversalTime(), item.SourceIp, item.SourcePort,
        item.AdapterKey, item.DestinationPort);

    private static OverviewConnectionRow FromAuthenticationFailure(InteractionEvent item) => FromEvent(item) with
    {
        Username = item.Username,
        CredentialArtifactId = item.CredentialArtifactId,
        MaterialType = item.MaterialType,
    };
}
