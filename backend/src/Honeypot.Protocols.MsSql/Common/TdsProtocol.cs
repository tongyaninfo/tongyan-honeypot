using System.Buffers.Binary;
using System.Text;
using Honeypot.Protocols.MsSql.Models;

namespace Honeypot.Protocols.MsSql.Common;

/// <summary>PreLogin、LOGIN7 与失败 token 的有界编解码，不建立数据库会话。</summary>
internal static class TdsProtocol
{
    private static readonly Encoding StrictUnicode = new UnicodeEncoding(false, false, true);

    public static byte ReadEncryption(ReadOnlySpan<byte> payload)
    {
        var options = new List<(byte Token, int Offset, int Length)>();
        var position = 0;
        while (position < payload.Length && payload[position] != 0xFF)
        {
            if (position + 5 > payload.Length) throw new InvalidDataException("Invalid PRELOGIN option table.");
            var token = payload[position];
            if (options.Any(item => item.Token == token)) throw new InvalidDataException("Duplicate PRELOGIN option.");
            options.Add((token, BinaryPrimitives.ReadUInt16BigEndian(payload[(position + 1)..]),
                BinaryPrimitives.ReadUInt16BigEndian(payload[(position + 3)..])));
            position += 5;
        }
        if (position >= payload.Length || options.Count == 0 || options[0].Token != 0)
            throw new InvalidDataException("PRELOGIN VERSION is required.");
        position++;
        foreach (var option in options)
            if (option.Offset < position || option.Offset > payload.Length || option.Length > payload.Length - option.Offset)
                throw new InvalidDataException("Invalid PRELOGIN option range.");
        if (options[0].Length != 6) throw new InvalidDataException("Invalid PRELOGIN VERSION.");
        var encryption = options.SingleOrDefault(item => item.Token == 1);
        if (encryption.Length != 1 || payload[encryption.Offset] > 3)
            throw new InvalidDataException("Unsupported PRELOGIN encryption option.");
        return payload[encryption.Offset];
    }

    public static byte[] BuildPreLogin(byte encryption)
    {
        // 只宣告本适配器实现的选项；MARS 关闭，TLS 在后续认证前完成。
        byte[] payload = [0, 0, 16, 0, 6, 1, 0, 22, 0, 1, 4, 0, 23, 0, 1, 0xFF,
            15, 0, 0x10, 0, 0, 0, encryption, 0];
        return payload;
    }

    public static TdsLoginMessage ReadLogin(ReadOnlySpan<byte> payload)
    {
        if (payload.Length < 86 || payload.Length > 131071 || BinaryPrimitives.ReadUInt32LittleEndian(payload) != payload.Length)
            throw new InvalidDataException("Invalid LOGIN7 length.");
        var version = BinaryPrimitives.ReadUInt32LittleEndian(payload[4..]);
        if (version is not (0x70000000 or 0x71000001 or 0x72090002 or 0x730A0003 or 0x730B0003 or 0x74000004))
            throw new InvalidDataException("Unsupported LOGIN7 TDS version.");
        var minimum = version >= 0x72000000 ? 94 : 86;
        if (payload.Length < minimum) throw new InvalidDataException("Truncated LOGIN7 fixed header.");
        var packetSize = BinaryPrimitives.ReadUInt32LittleEndian(payload[8..]);
        if (packetSize is < 512 or > 32767) throw new InvalidDataException("Invalid LOGIN7 packet size.");
        var hostname = ReadText(payload, 36, minimum);
        var username = ReadText(payload, 40, minimum);
        var password = ReadText(payload, 44, minimum, password: true);
        var application = ReadText(payload, 48, minimum);
        _ = ReadText(payload, 52, minimum);
        _ = ReadText(payload, 60, minimum);
        _ = ReadText(payload, 64, minimum);
        var database = ReadText(payload, 68, minimum);
        _ = ReadText(payload, 82, minimum, maximumCharacters: 260);
        var changedPassword = minimum >= 94 && (payload[27] & 1) != 0
            ? ReadText(payload, 86, minimum, password: true) : null;
        var sspiOffset = BinaryPrimitives.ReadUInt16LittleEndian(payload[78..]);
        var sspiLength = (uint)BinaryPrimitives.ReadUInt16LittleEndian(payload[80..]);
        if (sspiLength == ushort.MaxValue && minimum >= 94)
            sspiLength = BinaryPrimitives.ReadUInt32LittleEndian(payload[90..]);
        if (sspiLength > payload.Length || (sspiLength > 0 && sspiOffset < minimum) || sspiOffset > payload.Length || sspiLength > payload.Length - sspiOffset)
            throw new InvalidDataException("Invalid LOGIN7 SSPI range.");
        var integrated = (payload[25] & 0x80) != 0;
        if (!integrated && sspiLength != 0) throw new InvalidDataException("Unexpected LOGIN7 SSPI data.");
        var federated = false;
        if ((payload[27] & 0x10) != 0)
        {
            // FeatureExt 的 offset pair 指向一个 DWORD 指针，不能把扩展认证材料当 SQL 密码。
            var extension = ReadRange(payload, 56, minimum, 1, 4);
            if (extension.Length != 4) throw new InvalidDataException("Invalid LOGIN7 feature pointer.");
            var featureOffset = BinaryPrimitives.ReadUInt32LittleEndian(extension);
            if (featureOffset < minimum || featureOffset >= payload.Length) throw new InvalidDataException("Invalid LOGIN7 feature range.");
            var offset = (int)featureOffset;
            while (payload[offset] != 0xFF)
            {
                if (payload.Length - offset < 5) throw new InvalidDataException("Truncated LOGIN7 feature.");
                var length = BinaryPrimitives.ReadUInt32LittleEndian(payload[(offset + 1)..]);
                if (length > payload.Length - offset - 5) throw new InvalidDataException("Invalid LOGIN7 feature length.");
                federated |= payload[offset] == 2;
                offset += 5 + (int)length;
                if (offset >= payload.Length) throw new InvalidDataException("Missing LOGIN7 feature terminator.");
            }
        }
        return new(version, username, password, changedPassword, database, hostname, application, integrated,
            payload.Slice(sspiOffset, (int)sspiLength).ToArray(), federated);
    }

    private static string ReadText(ReadOnlySpan<byte> payload, int pair, int minimum, bool password = false, int maximumCharacters = 128)
    {
        var bytes = ReadRange(payload, pair, minimum, 2, maximumCharacters);
        if (!password) return StrictUnicode.GetString(bytes);
        var decoded = bytes.ToArray();
        try
        {
            // LOGIN7 密码为可逆混淆：先 XOR，再交换高低半字节，保留空格和 Unicode。
            for (var index = 0; index < decoded.Length; index++)
            {
                var value = decoded[index] ^ 0xA5;
                decoded[index] = (byte)((value << 4) | (value >> 4));
            }
            return StrictUnicode.GetString(decoded);
        }
        finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(decoded); }
    }

    private static ReadOnlySpan<byte> ReadRange(ReadOnlySpan<byte> payload, int pair, int minimum, int unit, int maximum)
    {
        var offset = BinaryPrimitives.ReadUInt16LittleEndian(payload[pair..]);
        var count = BinaryPrimitives.ReadUInt16LittleEndian(payload[(pair + 2)..]);
        var length = count * unit;
        if (count > maximum || offset > payload.Length || length > payload.Length - offset || (length > 0 && offset < minimum))
            throw new InvalidDataException("Invalid LOGIN7 field range.");
        return payload.Slice(offset, length);
    }

    public static byte[] BuildLoginError(string? username, string hostname, uint version)
    {
        var user = username ?? string.Empty;
        if (user.Length > 128) user = user[..128];
        if (hostname.Length > 128) hostname = hostname[..128];
        var message = $"Login failed for user '{user}'.";
        using var content = new MemoryStream();
        using (var writer = new BinaryWriter(content, Encoding.Unicode, true))
        {
            writer.Write(18456);
            writer.Write((byte)1);
            writer.Write((byte)14);
            writer.Write((ushort)message.Length);
            writer.Write(Encoding.Unicode.GetBytes(message));
            writer.Write((byte)hostname.Length);
            writer.Write(Encoding.Unicode.GetBytes(hostname));
            writer.Write((byte)0);
            writer.Write((ushort)0);
            if (version >= 0x72000000) writer.Write((ushort)0);
        }
        using var response = new MemoryStream();
        using var output = new BinaryWriter(response);
        output.Write((byte)0xAA);
        output.Write(checked((ushort)content.Length));
        output.Write(content.ToArray());
        output.Write((byte)0xFD);
        output.Write((ushort)2); // DONE_ERROR，且绝不发送 LOGINACK。
        output.Write((ushort)0);
        output.Write((uint)0);
        if (version >= 0x72000000) output.Write((uint)0);
        return response.ToArray();
    }
}
