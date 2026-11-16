namespace Honeypot.Api.Models;

public sealed record QueryPageResult<T>(IReadOnlyList<T> Items, int Total, int Page, int PageSize);
