namespace Honeypot.Api.Models;

public sealed record InteractionEventQuery(
    string? SourceIp = null,
    string? AdapterKey = null,
    string? EventType = null,
    int? DestinationPort = null,
    IReadOnlySet<string>? ConnectionIds = null,
    DateTimeOffset? FromUtc = null,
    DateTimeOffset? ToUtc = null,
    int? Page = null,
    int? PageSize = null);
