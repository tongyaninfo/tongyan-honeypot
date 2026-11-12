using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using Honeypot.Protocol.Abstractions.Models;

namespace Honeypot.Api.Common;

/// <summary>对已保存的绑定快照计算稳定摘要，防止管理员改端口后旧授权被自动扩大。</summary>
public static class McpInstanceScope
{
    public static string BindingFingerprint(ServiceInstance instance) => Convert.ToHexString(SHA256.HashData(
        JsonSerializer.SerializeToUtf8Bytes(new
        {
            instance.AdapterKey,
            Bindings = instance.Bindings.OrderBy(binding => binding.ListenerId, StringComparer.Ordinal),
        })));

    public static bool CanActivate(ServiceInstance instance, IReadOnlySet<IPAddress> configuredAddresses)
    {
        if (!string.Equals(instance.Profile.AuthMode, "AlwaysFail", StringComparison.OrdinalIgnoreCase)) return false;
        var enabled = instance.Bindings.Where(binding => binding.Enabled).ToArray();
        return enabled.Length > 0 && enabled.All(binding =>
            string.Equals(binding.BindAddress, "localhost", StringComparison.OrdinalIgnoreCase) ||
            (IPAddress.TryParse(binding.BindAddress, out var parsed) && IsAllowed(Normalize(parsed), configuredAddresses)));
    }

    public static IPAddress Normalize(IPAddress address) => address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;

    private static bool IsAllowed(IPAddress address, IReadOnlySet<IPAddress> configuredAddresses) =>
        IPAddress.IsLoopback(address) || (IsPrivate(address) && configuredAddresses.Contains(address));

    private static bool IsPrivate(IPAddress address)
    {
        if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6) return address.IsIPv6UniqueLocal;
        var bytes = address.GetAddressBytes();
        return bytes[0] == 10 || (bytes[0] == 172 && bytes[1] is >= 16 and <= 31) || (bytes[0] == 192 && bytes[1] == 168);
    }
}
