using System.Net;
using System.Net.Sockets;
using Honeypot.Shared.Models;

namespace Honeypot.Api.Common;

public static class IPLocationAddress
{
    public static bool TryParse(string? input, out IPAddress address)
    {
        address = IPAddress.None;
        if (string.IsNullOrWhiteSpace(input) || input.Length > 64 || input.IndexOfAny(['%', '[', ']']) >= 0 ||
            !IPAddress.TryParse(input, out var parsed)) return false;
        // .NET 接受整数、短 IPv4 等历史形式；输入边界只接受四段十进制或 IPv6。
        var ipv4Part = input[(input.LastIndexOf(':') + 1)..];
        if ((parsed.AddressFamily == AddressFamily.InterNetwork || input.Contains('.')) &&
            (ipv4Part.Split('.') is not { Length: 4 } octets || octets.Any(part => part.Length == 0 || part.Length > 3 ||
                part.Length > 1 && part[0] == '0' || !part.All(char.IsAsciiDigit))))
            return false;
        address = parsed.IsIPv4MappedToIPv6 ? parsed.MapToIPv4() : parsed;
        return true;
    }

    public static IPLocationResult? Classify(string input, out string normalized)
    {
        normalized = input;
        if (input.Contains('/'))
        {
            var pieces = input.Split('/');
            if (pieces.Length == 2 && TryParse(pieces[0], out var network) &&
                int.TryParse(pieces[1], out var prefix) && pieces[1].All(char.IsAsciiDigit) &&
                prefix >= 0 && prefix <= (pieces[0].Contains(':') ? 128 : 32))
                return new(input, "network", "网段");
            return new(input, "invalid", "无效 IP 地址");
        }
        if (!TryParse(input, out var address)) return new(input, "invalid", "无效 IP 地址");
        normalized = address.ToString();
        var b = address.GetAddressBytes();
        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            if (b[0] == 10 || b[0] == 172 && b[1] is >= 16 and <= 31 || b[0] == 192 && b[1] == 168)
                return new(input, "private", "内网地址");
            if (b[0] is 0 or 127 || b[0] >= 224 || b[0] == 100 && b[1] is >= 64 and <= 127 ||
                b[0] == 169 && b[1] == 254 || b[0] == 192 && (b[1] == 0 && b[2] is 0 or 2 || b[1] == 88 && b[2] == 99) ||
                b[0] == 198 && (b[1] is 18 or 19 || b[1] == 51 && b[2] == 100) || b[0] == 203 && b[1] == 0 && b[2] == 113)
                return new(input, "reserved", "保留地址");
        }
        else
        {
            if ((b[0] & 0xfe) == 0xfc) return new(input, "private", "内网地址");
            if ((b[0] & 0xe0) != 0x20 ||
                b[0] == 0x20 && b[1] == 0x01 && (b[2] < 2 || b[2] == 0x0d && b[3] == 0xb8) ||
                b[0] == 0x20 && b[1] == 0x02 || b[0] == 0x3f && b[1] == 0xff && (b[2] & 0xf0) == 0)
                return new(input, "reserved", "保留地址");
        }
        return null;
    }
}
