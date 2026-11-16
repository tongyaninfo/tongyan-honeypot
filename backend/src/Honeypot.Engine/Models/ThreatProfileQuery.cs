namespace Honeypot.Engine.Models;

public enum ThreatProfileSort
{
    LastSeen,
    Risk,
    RiskThenAuthenticationAttempts,
}

public sealed record ThreatProfileQuery(
    int Page = 1,
    int PageSize = 20,
    ThreatProfileSort Sort = ThreatProfileSort.LastSeen,
    string? SourceIp = null,
    int MinimumScore = 0,
    string? Status = null,
    DateTimeOffset? FromUtc = null,
    DateTimeOffset? ToUtc = null)
{
    public int PageNumber => Math.Max(Page, 1);
    public int BoundedPageSize => Math.Clamp(PageSize, 1, 100);
    public long Offset => ((long)PageNumber - 1) * BoundedPageSize;
}

public sealed record ThreatProfilePage(IReadOnlyList<ThreatIpProfile> Items, int Total, int Page, int PageSize);
