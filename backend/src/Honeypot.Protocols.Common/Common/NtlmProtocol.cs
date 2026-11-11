using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Honeypot.Protocols.Common;

/// <summary>RDP/MSSQL 共用的 NTLM 有界解析与挑战构造；只采集响应，不验证口令或访问真实域。</summary>
public static class NtlmProtocol
{
    private static readonly byte[] Signature = Encoding.ASCII.GetBytes("NTLMSSP\0");

    public static bool TryParse(ReadOnlySpan<byte> token, out NtlmMessage message)
    {
        message = default;
        if (token.Length < 16 || !token[..8].SequenceEqual(Signature)) return false;
        var type = BinaryPrimitives.ReadUInt32LittleEndian(token[8..12]);
        if (type == 1)
        {
            if (token.Length < 32 || ReadBuffer(token, 16, 32) is null || ReadBuffer(token, 24, 32) is null) return false;
            var flags = BinaryPrimitives.ReadUInt32LittleEndian(token[12..16]);
            if ((flags & 0x02000000) != 0 && token.Length < 40) return false;
            message = new(type, flags, null, null, null, null, token.ToArray());
            return true;
        }
        if (type != 3 || token.Length < 64) return false;
        var negotiateFlags = BinaryPrimitives.ReadUInt32LittleEndian(token[60..64]);
        var minimum = (negotiateFlags & 0x02000000) != 0 ? 72 : 64;
        if (token.Length < minimum) return false;
        var lm = ReadBuffer(token, 12, minimum);
        var nt = ReadBuffer(token, 20, minimum);
        var domain = ReadBuffer(token, 28, minimum);
        var user = ReadBuffer(token, 36, minimum);
        var workstation = ReadBuffer(token, 44, minimum);
        var sessionKey = ReadBuffer(token, 52, minimum);
        if (lm is null || nt is null || domain is null || user is null || workstation is null || sessionKey is null) return false;
        var unicode = (negotiateFlags & 1) != 0;
        if (unicode && ((domain.Length | user.Length | workstation.Length) & 1) != 0) return false;
        var encoding = unicode ? Encoding.Unicode : Encoding.Latin1;
        message = new(type, negotiateFlags, encoding.GetString(domain), encoding.GetString(user),
            encoding.GetString(workstation), nt, token.ToArray());
        return true;
    }

    public static byte[] BuildChallenge(string hostName, uint clientFlags, string? domain = null)
    {
        var computer = hostName.Split('.')[0];
        if (computer.Length > 15) computer = computer[..15];
        computer = computer.ToUpperInvariant();
        domain = string.IsNullOrWhiteSpace(domain) ? computer : domain;
        // 只返回双方支持的特性；不继承客户端保留位，也不宣称 LM_KEY/DATAGRAM。
        const uint supported = 0xE2888237;
        var flags = (clientFlags & supported) | 0x00820204u;
        flags |= (clientFlags & 1) != 0 || (clientFlags & 2) == 0 ? 1u : 2u;
        if ((flags & 1) != 0) flags &= ~2u;
        var targetName = ((flags & 1) != 0 ? Encoding.Unicode : Encoding.Latin1).GetBytes(domain);
        using var targetInfo = new MemoryStream();
        AddPair(targetInfo, 1, Encoding.Unicode.GetBytes(computer));
        AddPair(targetInfo, 2, Encoding.Unicode.GetBytes(domain));
        AddPair(targetInfo, 3, Encoding.Unicode.GetBytes(hostName));
        AddPair(targetInfo, 4, Encoding.Unicode.GetBytes(domain));
        var timestamp = new byte[8];
        BinaryPrimitives.WriteInt64LittleEndian(timestamp, DateTimeOffset.UtcNow.ToFileTime());
        AddPair(targetInfo, 7, timestamp);
        AddPair(targetInfo, 0, []);
        var info = targetInfo.ToArray();
        var message = new byte[56 + targetName.Length + info.Length];
        Signature.CopyTo(message, 0);
        BinaryPrimitives.WriteUInt32LittleEndian(message.AsSpan(8), 2);
        WriteBuffer(message, 12, targetName.Length, 56);
        BinaryPrimitives.WriteUInt32LittleEndian(message.AsSpan(20), flags);
        RandomNumberGenerator.Fill(message.AsSpan(24, 8));
        WriteBuffer(message, 40, info.Length, 56 + targetName.Length);
        if ((flags & 0x02000000) != 0)
        {
            message[48] = 10;
            BinaryPrimitives.WriteUInt16LittleEndian(message.AsSpan(50), 19045);
            message[55] = 15;
        }
        targetName.CopyTo(message, 56);
        info.CopyTo(message, 56 + targetName.Length);
        return message;
    }

    private static byte[]? ReadBuffer(ReadOnlySpan<byte> data, int field, int minimum)
    {
        var length = BinaryPrimitives.ReadUInt16LittleEndian(data[field..]);
        var maximum = BinaryPrimitives.ReadUInt16LittleEndian(data[(field + 2)..]);
        var offset = BinaryPrimitives.ReadUInt32LittleEndian(data[(field + 4)..]);
        if (length > maximum || offset > data.Length || length > data.Length - offset || (length > 0 && offset < minimum)) return null;
        return data.Slice((int)offset, length).ToArray();
    }

    private static void WriteBuffer(Span<byte> data, int field, int length, int offset)
    {
        BinaryPrimitives.WriteUInt16LittleEndian(data[field..], checked((ushort)length));
        BinaryPrimitives.WriteUInt16LittleEndian(data[(field + 2)..], checked((ushort)length));
        BinaryPrimitives.WriteUInt32LittleEndian(data[(field + 4)..], checked((uint)offset));
    }

    private static void AddPair(Stream stream, ushort id, byte[] value)
    {
        Span<byte> header = stackalloc byte[4];
        BinaryPrimitives.WriteUInt16LittleEndian(header, id);
        BinaryPrimitives.WriteUInt16LittleEndian(header[2..], checked((ushort)value.Length));
        stream.Write(header);
        stream.Write(value);
    }

    public readonly record struct NtlmMessage(uint Type, uint Flags, string? Domain, string? Username,
        string? Workstation, byte[]? NtResponse, byte[] Raw);
}
