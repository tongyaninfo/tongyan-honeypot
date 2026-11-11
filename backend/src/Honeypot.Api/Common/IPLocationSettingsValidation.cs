using System.Net;
using Honeypot.Shared.Models;

namespace Honeypot.Api.Common;

public static class IPLocationSettingsValidation
{
    private static readonly string[] Databases = ["CZ88", "ip2location", "ip2region", "dbip", "ipinfo", "geolite2"];

    public static bool TryNormalize(IPLocationSettings settings, out IPLocationSettings normalized)
    {
        normalized = settings;
        var protocol = settings.Protocol?.Trim().ToLowerInvariant();
        var host = settings.Host?.Trim();
        var database = Databases.FirstOrDefault(value => value.Equals(settings.Database?.Trim(), StringComparison.OrdinalIgnoreCase));
        if (protocol is not ("http" or "https") || string.IsNullOrWhiteSpace(host) || host.Length > 253 ||
            host.Any(char.IsWhiteSpace) || host.IndexOfAny(['/', '\\', '?', '#', '@', '%', '[', ']']) >= 0 ||
            settings.Port is < 1 or > 65535 || !double.IsFinite(settings.TimeoutSeconds) ||
            settings.TimeoutSeconds is < 0.1 or > 30 || database is null)
            return false;
        // 主机独立填写，不接受 URL、用户信息和内嵌端口；允许管理员配置内网服务。
        if (host.Contains(':') ? !IPAddress.TryParse(host, out _) : Uri.CheckHostName(host) == UriHostNameType.Unknown)
            return false;
        normalized = settings with { Protocol = protocol, Host = host, Database = database };
        return true;
    }
}
