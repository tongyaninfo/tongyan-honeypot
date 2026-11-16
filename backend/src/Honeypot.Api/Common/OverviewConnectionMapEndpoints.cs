using Honeypot.Api.Models;
using Honeypot.Api.Service;
using Honeypot.Shared.Models;

namespace Honeypot.Api.Common;

public static class OverviewConnectionMapEndpoints
{
    internal const string Path = "/api/v1/metrics/overview/connection-map";
    private const int DefaultWindowSeconds = 600;
    private const int MaximumEvents = 100;

    public static void MapOverviewConnectionMapEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet(Path, (string? windowSeconds, HttpContext context, IInteractionEventStore events, IIPLocationResolver locations,
            IConnectionMapTarget target, TimeProvider clock) =>
        {
            context.Response.Headers.CacheControl = "no-store";
            if (context.Items["CurrentUser"] is not AuthenticatedUser)
                return Results.Json(ApiResult<object>.Fail("UNAUTHORIZED", "请先登录。"), statusCode: 401);

            var window = DefaultWindowSeconds;
            if (windowSeconds is not null && (!int.TryParse(windowSeconds, out window) || window is not (60 or 600 or 7200 or 86400)))
                return Results.BadRequest(ApiResult<object>.Fail("INVALID_WINDOW", "地图时间范围只支持最近 60 秒、10 分钟、2 小时或 24 小时。"));

            return Results.Ok(ApiResult<ConnectionMapSnapshot>.Ok(Read(events, locations, target, clock.GetUtcNow(), window)));
        });
    }

    private static ConnectionMapSnapshot Read(IInteractionEventStore events, IIPLocationResolver locations,
        IConnectionMapTarget target, DateTimeOffset now, int windowSeconds)
    {
        var start = now.AddSeconds(-windowSeconds);
        // 一次 TCP 接纳代表一个连接，后续握手、认证、断开不重复计数。
        var candidates = events.GetAll()
            .Where(item => item.OccurredAtUtc >= start && item.OccurredAtUtc <= now &&
                !string.IsNullOrWhiteSpace(item.ConnectionId) && OverviewActivityProjection.IsConnectionAccepted(item))
            .OrderByDescending(item => item.OccurredAtUtc).ThenBy(item => item.EventId, StringComparer.Ordinal)
            .DistinctBy(item => item.ConnectionId, StringComparer.Ordinal)
            .Select(item =>
            {
                // 复用现有地址边界，并在入队前合并同一公网地址的不同写法。
                var classified = IPLocationAddress.Classify(item.SourceIp ?? "", out var normalized);
                return (Event: item, Ip: normalized, Classification: classified?.Status);
            }).ToArray();
        var publicIps = candidates.Where(item => item.Classification is null)
            .Select(item => item.Ip).Distinct(StringComparer.Ordinal).ToArray();
        // 每个来源都读缓存；尚无结果的地址由解析器有界入队，HTTP 线程不等待上游。
        var batch = locations.ResolveForMap(publicIps);
        var results = batch.Items.ToDictionary(item => item.Ip, StringComparer.Ordinal);
        var pending = 0;
        var deferred = 0;
        var special = 0;
        var unknown = 0;
        var points = new List<ConnectionMapEvent>();

        foreach (var candidate in candidates)
        {
            if (candidate.Classification is "private" or "reserved" or "network")
            {
                special++;
                continue;
            }
            if (candidate.Classification is not null || !batch.Enabled || !results.TryGetValue(candidate.Ip, out var location))
            {
                unknown++;
                continue;
            }
            if (location.Status is "pending" or "busy" or "deferred")
            {
                pending++;
                if (location.Status is "busy" or "deferred") deferred++;
                continue;
            }
            if (location.Status != "resolved" || !IPLocationAddress.HasCoordinates(location.Latitude, location.Longitude))
            {
                unknown++;
                continue;
            }

            var label = string.Join(" · ", new[] { location.Country, location.Province, location.City, location.District }
                .Where(value => !string.IsNullOrWhiteSpace(value)).Distinct(StringComparer.Ordinal));
            var item = candidate.Event;
            points.Add(new(item.ConnectionId, item.OccurredAtUtc.ToUniversalTime(), item.AdapterKey,
                location.Longitude!.Value, location.Latitude!.Value, label, location.Source, location.Version,
                candidate.Ip, location.Country));
        }

        var flights = points.Take(MaximumEvents).ToArray();
        var coverage = new ConnectionMapCoverage(candidates.Length, points.Count, unknown, special, pending, points.Count - flights.Length)
        {
            Deferred = deferred,
        };
        return new(now.ToUniversalTime(), windowSeconds, target.GetSnapshot(), flights, coverage, batch.Enabled)
        {
            Origins = ConnectionMapOriginProjection.Build(points),
            AdapterKeys = points.Select(item => item.AdapterKey).Distinct(StringComparer.OrdinalIgnoreCase)
                .Order(StringComparer.OrdinalIgnoreCase).ToArray(),
        };
    }
}
