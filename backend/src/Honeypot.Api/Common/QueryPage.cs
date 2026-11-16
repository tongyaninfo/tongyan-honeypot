using Honeypot.Api.Models;

namespace Honeypot.Api.Common;

public static class QueryPage
{
    public static (int Page, int PageSize, long Offset) Bounds(int? page, int? pageSize)
    {
        var size = Math.Clamp(pageSize ?? 20, 1, 100);
        var number = Math.Max(page ?? 1, 1);
        return (number, size, ((long)number - 1) * size);
    }

    public static QueryPageResult<T> Create<T>(IEnumerable<T> source, int? page, int? pageSize)
    {
        var (number, size, offset) = Bounds(page, pageSize);
        var items = source as IReadOnlyList<T> ?? source.ToArray();
        var pageItems = offset < items.Count ? items.Skip((int)offset).Take(size).ToArray() : [];
        return new(pageItems, items.Count, number, size);
    }
}
