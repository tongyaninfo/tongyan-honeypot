using System.Net;
using Honeypot.Shared.Models;

namespace Honeypot.Api.Common;

public static class SyslogSettingsValidation
{
    public static bool TryNormalize(SyslogSettings? settings, out SyslogSettings normalized)
    {
        normalized = new();
        if (settings is null || settings.Targets is null || settings.Targets.Length > 3 ||
            settings.ConnectTimeoutSeconds is < 1 or > 60 || settings.WriteTimeoutSeconds is < 1 or > 60 ||
            settings.QueueCapacity is < 100 or > 100000 || settings.SpoolMaxBytes is < 1048576 or > 1073741824 ||
            settings.RetentionHours is < 1 or > 168) return false;
        var targets = new List<SyslogTarget>();
        var ids = new HashSet<string>(StringComparer.Ordinal);
        foreach (var target in settings.Targets)
        {
            if (target is null) return false;
            var id = target.Id?.Trim();
            var name = target.Name?.Trim();
            var host = target.Host?.Trim();
            if (string.IsNullOrWhiteSpace(id) || id.Length > 64 || id.Any(value => !char.IsAsciiLetterOrDigit(value) && value is not '-' and not '_') || !ids.Add(id) ||
                string.IsNullOrWhiteSpace(name) || name.Length > 64 || name.Any(char.IsControl) ||
                string.IsNullOrWhiteSpace(host) || host.Length > 253 || host.Any(value => char.IsWhiteSpace(value) || char.IsControl(value)) ||
                host.IndexOfAny(['/', '\\', '?', '#', '@', '%', '[', ']']) >= 0 || target.Port is < 1 or > 65535 ||
                !Enum.IsDefined(target.Protocol)) return false;
            // 主机与端口分开；允许内网 IP，不接受 URL、凭据或 IPv6 zone id。
            if (host.Contains(':') ? !IPAddress.TryParse(host, out _) : Uri.CheckHostName(host) == UriHostNameType.Unknown) return false;
            targets.Add(target with { Id = id, Name = name, Host = host, IgnoreSslErrors = target.Protocol == SyslogProtocol.Tls && target.IgnoreSslErrors,
                IgnoredSeverities = [], Facility = SyslogTarget.DefaultFacility });
        }
        if (settings.Enabled && !targets.Any(target => target.Enabled)) return false;
        normalized = settings with { Targets = targets.ToArray() };
        return true;
    }
}
