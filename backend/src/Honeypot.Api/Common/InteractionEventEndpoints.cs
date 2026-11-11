using Honeypot.Api.Service;
using Honeypot.Protocol.Abstractions.Models;
using Honeypot.Shared.Models;

namespace Honeypot.Api.Common;

public static class InteractionEventEndpoints
{
    public static void MapInteractionEventEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/api/v1/events", (string? sourceIp, string? adapterKey, string? eventType,
            int? destinationPort, string? view, IInteractionEventStore store) =>
        {
            if (!string.IsNullOrEmpty(view) && view != "activity" && view != "raw")
                return Results.BadRequest(ApiResult<object>.Fail("INVALID_VIEW", "事件视图必须是 activity 或 raw。"));

            var events = store.GetAll().Where(item =>
                (string.IsNullOrWhiteSpace(sourceIp) || item.SourceIp.Equals(sourceIp, StringComparison.OrdinalIgnoreCase)) &&
                (string.IsNullOrWhiteSpace(adapterKey) || item.AdapterKey.Equals(adapterKey, StringComparison.OrdinalIgnoreCase)) &&
                (!destinationPort.HasValue || item.DestinationPort == destinationPort.Value));

            if (view == "activity")
            {
                // 先形成行为，再按代表事件类型筛选，避免过滤掉认证步骤后产生多余的连接行。
                var activities = InteractionActivityProjection.Build(events)
                    .Where(item => string.IsNullOrWhiteSpace(eventType) || item.EventType.Equals(eventType, StringComparison.OrdinalIgnoreCase))
                    .ToArray();
                return Results.Ok(ApiResult<object>.Ok(new { items = activities, total = activities.Length, page = 1, pageSize = activities.Length }));
            }

            var items = events.Where(item => string.IsNullOrWhiteSpace(eventType) || item.EventType.Equals(eventType, StringComparison.OrdinalIgnoreCase)).ToArray();
            return Results.Ok(ApiResult<object>.Ok(new { items, total = items.Length, page = 1, pageSize = items.Length }));
        });

        endpoints.MapGet("/api/v1/connections/{connectionId}/events", (string connectionId, IInteractionEventStore store) =>
            Results.Ok(ApiResult<IReadOnlyCollection<InteractionEvent>>.Ok(store.GetByConnectionId(connectionId))));
    }
}
