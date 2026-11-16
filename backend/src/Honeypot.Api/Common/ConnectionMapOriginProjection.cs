using System.Globalization;
using Honeypot.Api.Models;

namespace Honeypot.Api.Common;

internal static class ConnectionMapOriginProjection
{
    private const int MaximumOrigins = 400;
    private const int MaximumSources = 12;
    // 单位为百分之一度。15° 的经纬度范围最多覆盖 25 × 13 格。
    private static readonly int[] CellSizes = [1, 10, 25, 100, 200, 500, 1000, 1500];

    public static ConnectionMapOrigin[] Build(IReadOnlyList<ConnectionMapEvent> newestFirst)
    {
        var size = CellSizes.First(cellSize => newestFirst.Select(item => CellFor(item, cellSize))
            .Distinct().Take(MaximumOrigins + 1).Count() <= MaximumOrigins);
        return newestFirst.GroupBy(item => CellFor(item, size)).Select(cell => ToOrigin(cell, size)).ToArray();
    }

    private static (int Longitude, int Latitude) CellFor(ConnectionMapEvent item, int size) => (
        CellIndex(item.Longitude, size), CellIndex(item.Latitude, size));

    private static int CellIndex(double degrees, int size) =>
        (int)Math.Round(degrees * 100 / size, MidpointRounding.AwayFromZero);

    private static ConnectionMapOrigin ToOrigin(IGrouping<(int Longitude, int Latitude), ConnectionMapEvent> cell, int size)
    {
        var latest = cell.First();
        var ips = new HashSet<string>(StringComparer.Ordinal);
        var sources = new List<ConnectionMapSource>(MaximumSources);
        var multipleLocations = false;
        var count = 0;
        foreach (var item in cell)
        {
            count++;
            if (ips.Add(item.SourceIp) && sources.Count < MaximumSources)
                sources.Add(new(item.SourceIp, item.Country));
            if (item.Longitude != latest.Longitude || item.Latitude != latest.Latitude || item.LocationLabel != latest.LocationLabel)
                multipleLocations = true;
        }

        // 粗网格采用实际存在的代表坐标，并标注汇总，避免把整格误读成代表城市。
        var label = size > 1 && multipleLocations ? "区域汇总" : latest.LocationLabel;
        var id = string.Create(CultureInfo.InvariantCulture, $"{size}:{cell.Key.Longitude}:{cell.Key.Latitude}");
        return new(id, latest.Longitude, latest.Latitude, label, latest.AdapterKey, count, ips.Count, sources);
    }
}
