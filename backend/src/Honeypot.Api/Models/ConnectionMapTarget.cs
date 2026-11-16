namespace Honeypot.Api.Models;

/// <summary>地图公开的蜜罐节点状态，仅包含位置和来源类型。</summary>
public sealed record ConnectionMapTarget(
    string Status, string? Label = null, double? Latitude = null, double? Longitude = null,
    string? Source = null, bool Stale = false, DateTimeOffset? UpdatedAtUtc = null);
