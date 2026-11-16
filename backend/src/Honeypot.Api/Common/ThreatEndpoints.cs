using Honeypot.Engine.Models;
using Honeypot.Engine.Service;
using Honeypot.Shared.Models;

namespace Honeypot.Api.Common;

public static class ThreatEndpoints
{
    public static void MapThreatEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/api/v1/threats", (int? page, int? pageSize, string? sort, IThreatProfileStore store) =>
        {
            var order = sort == "risk" ? ThreatProfileSort.RiskThenAuthenticationAttempts : ThreatProfileSort.LastSeen;
            return Results.Ok(ApiResult<ThreatProfilePage>.Ok(store.Query(new(page ?? 1, pageSize ?? 20, order))));
        });

        endpoints.MapGet("/api/v1/threats/by-ip/{sourceIp}", (string sourceIp, IThreatProfileStore store) =>
        {
            var profile = store.GetByIp(sourceIp);
            return profile is null
                ? Results.NotFound(ApiResult<object>.Fail("NOT_FOUND", $"Threat IP '{sourceIp}' was not found."))
                : Results.Ok(ApiResult<ThreatIpProfile>.Ok(profile));
        });
    }
}
