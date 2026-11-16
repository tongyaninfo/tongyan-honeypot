using Honeypot.Engine.Models;
using Honeypot.Protocol.Abstractions.Models;

namespace Honeypot.Engine.Service;

public interface IThreatProfileStore
{
    ThreatIpProfile Apply(InteractionEvent interactionEvent);

    ThreatIpProfile Apply(InteractionEvent interactionEvent, out string? previousStatus)
    {
        previousStatus = GetByIp(interactionEvent.SourceIp)?.Status;
        return Apply(interactionEvent);
    }

    IReadOnlyCollection<ThreatIpProfile> GetAll();

    ThreatIpProfile? GetByIp(string sourceIp);

    int Count() => GetAll().Count;

    IReadOnlySet<string> GetObservedSources(IReadOnlyCollection<string> sourceIps)
    {
        var candidates = sourceIps.ToHashSet(StringComparer.OrdinalIgnoreCase);
        return GetAll().Select(item => item.SourceIp).Where(candidates.Contains).ToHashSet(StringComparer.OrdinalIgnoreCase);
    }

    ThreatProfilePage Query(ThreatProfileQuery query)
    {
        var matching = GetAll().Where(item =>
            (query.SourceIp is null || string.Equals(item.SourceIp, query.SourceIp, StringComparison.OrdinalIgnoreCase)) &&
            item.CurrentScore >= query.MinimumScore &&
            (query.Status is null || string.Equals(item.Status, query.Status, StringComparison.OrdinalIgnoreCase)) &&
            (query.FromUtc is null || item.LastSeenUtc >= query.FromUtc) &&
            (query.ToUtc is null || item.LastSeenUtc < query.ToUtc)).ToArray();
        if (query.Offset >= matching.Length) return new([], matching.Length, query.PageNumber, query.BoundedPageSize);
        var ordered = query.Sort switch
        {
            ThreatProfileSort.Risk => matching.OrderByDescending(item => item.CurrentScore).ThenByDescending(item => item.LastSeenUtc),
            ThreatProfileSort.RiskThenAuthenticationAttempts => matching.OrderByDescending(item => item.CurrentScore)
                .ThenByDescending(item => item.AuthenticationAttemptCount).ThenByDescending(item => item.LastSeenUtc),
            _ => matching.OrderByDescending(item => item.LastSeenUtc),
        };
        var items = ordered.ThenBy(item => item.SourceIp, StringComparer.Ordinal).Skip((int)query.Offset)
            .Take(query.BoundedPageSize).ToArray();
        return new(items, matching.Length, query.PageNumber, query.BoundedPageSize);
    }
}
