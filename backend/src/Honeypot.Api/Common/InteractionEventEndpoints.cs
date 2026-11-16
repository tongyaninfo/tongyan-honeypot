using Honeypot.Api.Service;
using Honeypot.Api.Models;
using Honeypot.Protocol.Abstractions.Models;
using Honeypot.Shared.Models;

namespace Honeypot.Api.Common;

public static class InteractionEventEndpoints
{
    public static void MapInteractionEventEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/api/v1/events", (string? sourceIp, string? adapterKey, string? eventType,
            int? destinationPort, string? view, string? connectionIds, int? page, int? pageSize, IInteractionEventStore store) =>
        {
            if (!string.IsNullOrEmpty(view) && view != "activity" && view != "raw")
                return Results.BadRequest(ApiResult<object>.Fail("INVALID_VIEW", "事件视图必须是 activity 或 raw。"));

            var ids = connectionIds?.Split(',', 101, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .ToHashSet(StringComparer.Ordinal);
            if (ids is { Count: > 100 } || ids?.Any(id => id.Length > 128) == true)
                return Results.BadRequest(ApiResult<object>.Fail("INVALID_CONNECTION_IDS", "每次最多可筛选 100 个连接编号。"));

            var query = new InteractionEventQuery(sourceIp, adapterKey, eventType, destinationPort, ids, Page: page, PageSize: pageSize);
            return Results.Ok(ApiResult<object>.Ok(view == "activity" ? store.ReadActivities(query) : store.ReadEvents(query)));
        });

        endpoints.MapGet("/api/v1/connections/{connectionId}/events", (string connectionId, IInteractionEventStore store) =>
            Results.Ok(ApiResult<IReadOnlyCollection<InteractionEvent>>.Ok(store.GetByConnectionId(connectionId))));
    }
}
