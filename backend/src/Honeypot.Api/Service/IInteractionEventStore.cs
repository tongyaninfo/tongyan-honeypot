using Honeypot.Api.Common;
using Honeypot.Api.Models;
using Honeypot.Protocol.Abstractions.Models;
using Honeypot.Protocol.Abstractions.Service;

namespace Honeypot.Api.Service;

public interface IInteractionEventStore : IInteractionEventSink
{
    IReadOnlyCollection<InteractionEvent> GetAll();

    IReadOnlyCollection<InteractionEvent> GetByConnectionId(string connectionId);

    QueryPageResult<InteractionEvent> ReadEvents(InteractionEventQuery query) => QueryPage.Create(
        MatchConnection(query).Where(item => MatchEvent(query, item.EventType, item.OccurredAtUtc))
            .OrderByDescending(item => item.OccurredAtUtc).ThenByDescending(item => item.Sequence)
            .ThenBy(item => item.EventId, StringComparer.Ordinal), query.Page, query.PageSize);

    QueryPageResult<RealtimeInteractionEvent> ReadActivities(InteractionEventQuery query) => QueryPage.Create(
        InteractionActivityProjection.Build(MatchConnection(query))
            .Where(item => MatchEvent(query, item.EventType, item.OccurredAtUtc)), query.Page, query.PageSize);

    private IEnumerable<InteractionEvent> MatchConnection(InteractionEventQuery query) => GetAll().Where(item =>
        (query.ConnectionIds is null || query.ConnectionIds.Contains(item.ConnectionId)) &&
        Matches(item.SourceIp, query.SourceIp) && Matches(item.AdapterKey, query.AdapterKey) &&
        (query.DestinationPort is null || item.DestinationPort == query.DestinationPort));

    private static bool MatchEvent(InteractionEventQuery query, string type, DateTimeOffset occurredAt) =>
        Matches(type, query.EventType) && (query.FromUtc is null || occurredAt >= query.FromUtc) &&
        (query.ToUtc is null || occurredAt < query.ToUtc);

    private static bool Matches(string actual, string? filter) =>
        string.IsNullOrWhiteSpace(filter) || actual.Equals(filter, StringComparison.OrdinalIgnoreCase);
}
