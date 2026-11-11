using Honeypot.Protocol.Abstractions.Models;

namespace Honeypot.Protocols.Common;

/// <summary>对外协议人格与管理台建议值使用同一来源；显式配置优先。</summary>
public static class ProtocolFingerprint
{
    public static string HostName(ServiceProfile profile) => string.IsNullOrWhiteSpace(profile.AdvertisedHostName)
        ? ServiceAdapterDefaults.For(profile.AdapterKey).HostName : profile.AdvertisedHostName.Trim();

    public static string Product(ServiceProfile profile) => IsDefault(profile.AdvertisedProduct, "Honeypot Service")
        ? ServiceAdapterDefaults.For(profile.AdapterKey).Product : profile.AdvertisedProduct.Trim();

    public static string Version(ServiceProfile profile) => IsDefault(profile.AdvertisedVersion, "0.1.0")
        ? ServiceAdapterDefaults.For(profile.AdapterKey).ProductVersion : profile.AdvertisedVersion.Trim();

    private static bool IsDefault(string? value, string defaultValue) =>
        string.IsNullOrWhiteSpace(value) || string.Equals(value, defaultValue, StringComparison.OrdinalIgnoreCase);
}
