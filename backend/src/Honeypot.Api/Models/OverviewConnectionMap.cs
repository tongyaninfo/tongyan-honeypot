namespace Honeypot.Api.Models;

/// <summary>已登录用户可查看绘图所需的近似地点、服务及来源 IP，不包含认证材料。</summary>
public sealed record ConnectionMapEvent(
    string Id, DateTimeOffset OccurredAtUtc, string AdapterKey, double Longitude, double Latitude,
    string LocationLabel, string? LocationSource, string? LocationVersion, string SourceIp, string Country);

public sealed record ConnectionMapSource(string Ip, string Country);

/// <summary>地图格内全部已定位连接的统计，附最近活动来源的有限列表。</summary>
public sealed record ConnectionMapOrigin(
    string Id, double Longitude, double Latitude, string LocationLabel, string AdapterKey,
    int ConnectionCount, int SourceIpCount, IReadOnlyList<ConnectionMapSource> Sources);

public sealed record ConnectionMapCoverage(
    int Observed, int Mapped, int Unknown, int Private, int Pending, int Omitted)
{
    public int Deferred { get; init; }
}

public sealed record ConnectionMapSnapshot(
    DateTimeOffset SampledAtUtc, int WindowSeconds, ConnectionMapTarget Target,
    IReadOnlyList<ConnectionMapEvent> Events, ConnectionMapCoverage Coverage, bool LocationEnabled)
{
    public IReadOnlyList<ConnectionMapOrigin> Origins { get; init; } = [];
    public IReadOnlyList<string> AdapterKeys { get; init; } = [];
}
