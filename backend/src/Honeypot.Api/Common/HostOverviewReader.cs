using System.Globalization;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using Honeypot.Api.Models;

namespace Honeypot.Api.Common;

internal static class HostOverviewReader
{
    public static HostOverview Read(DateTimeOffset now) => new(
        RuntimeInformation.OSDescription,
        GetHostName(),
        GetIpAddresses(),
        GetBootTimeUtc(now));

    private static string GetHostName()
    {
        try
        {
            return Environment.MachineName;
        }
        catch (InvalidOperationException)
        {
            return string.Empty;
        }
    }

    private static string[] GetIpAddresses()
    {
        try
        {
            return NetworkInterface.GetAllNetworkInterfaces()
                .Where(network => network.OperationalStatus == OperationalStatus.Up)
                .SelectMany(network => network.GetIPProperties().UnicastAddresses)
                .Select(item => item.Address)
                .Where(address => !IPAddress.IsLoopback(address) && !address.Equals(IPAddress.Any) && !address.Equals(IPAddress.IPv6Any))
                .Distinct()
                .OrderBy(address => address.AddressFamily != AddressFamily.InterNetwork)
                .ThenBy(address => address.IsIPv6LinkLocal)
                .ThenBy(address => address.ToString(), StringComparer.Ordinal)
                .Select(address => address.ToString())
                .ToArray();
        }
        catch (Exception error) when (error is NetworkInformationException or SocketException or PlatformNotSupportedException)
        {
            // 网卡信息不可用时仍返回其余总览数据。
            return [];
        }
    }

    private static DateTimeOffset? GetBootTimeUtc(DateTimeOffset now)
    {
        if (OperatingSystem.IsWindows())
        {
            // 当前目标框架为 .NET 10，Windows 的 TickCount64 包含休眠时间。
            return now.AddMilliseconds(-Environment.TickCount64);
        }

        if (!OperatingSystem.IsLinux()) return null;

        try
        {
            // btime 是当前环境所见的内核启动时间。容器环境下通常对应宿主机内核。
            foreach (var line in File.ReadLines("/proc/stat"))
            {
                if (line.StartsWith("btime ", StringComparison.Ordinal) &&
                    long.TryParse(line.AsSpan(6), NumberStyles.Integer, CultureInfo.InvariantCulture, out var seconds) &&
                    seconds > 0 && seconds <= now.ToUnixTimeSeconds())
                {
                    return DateTimeOffset.FromUnixTimeSeconds(seconds);
                }
            }
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            // 精简或隔离环境可能不提供 /proc/stat。
        }

        return null;
    }
}
