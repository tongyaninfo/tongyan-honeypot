using System.Buffers.Binary;
using System.Text;

namespace Honeypot.Protocols.Mongo.Common;

/// <summary>认证专用 BSON 编解码：限制深度、字段数和文档边界，不解释任何脚本或业务命令。</summary>
internal static class MongoBson
{
    private static readonly UTF8Encoding Utf8 = new(false, true);
    internal sealed record Binary(byte[] Data, byte Subtype = 0);
    internal sealed record Opaque(byte Type, byte[] Data);

    internal static Dictionary<string, object?> Decode(ReadOnlySpan<byte> data, out int consumed, int depth = 0)
    {
        if (depth > 12 || data.Length < 5) throw new InvalidDataException();
        var length = BinaryPrimitives.ReadInt32LittleEndian(data);
        if (length < 5 || length > data.Length || data[length - 1] != 0) throw new InvalidDataException();
        data = data[..length]; consumed = length;
        var fields = new Dictionary<string, object?>(StringComparer.Ordinal);
        var offset = 4;
        while (offset < length - 1)
        {
            if (fields.Count >= 1024) throw new InvalidDataException();
            var type = data[offset++];
            var key = CString(data, ref offset);
            object? value;
            switch (type)
            {
                case 1: Require(data, offset, 8); value = BitConverter.Int64BitsToDouble(BinaryPrimitives.ReadInt64LittleEndian(data[offset..])); offset += 8; break;
                case 2: value = String(data, ref offset); break;
                case 3:
                case 4:
                    value = Decode(data[offset..], out var nestedLength, depth + 1); offset += nestedLength; break;
                case 5:
                    Require(data, offset, 5);
                    var binaryLength = BinaryPrimitives.ReadInt32LittleEndian(data[offset..]); offset += 4;
                    var subtype = data[offset++]; Require(data, offset, binaryLength);
                    value = new Binary(data.Slice(offset, binaryLength).ToArray(), subtype); offset += binaryLength; break;
                case 7: Require(data, offset, 12); value = new Opaque(type, data.Slice(offset, 12).ToArray()); offset += 12; break;
                case 8:
                    Require(data, offset, 1); if (data[offset] > 1) throw new InvalidDataException(); value = data[offset++] == 1; break;
                case 9:
                case 17: Require(data, offset, 8); value = new Opaque(type, data.Slice(offset, 8).ToArray()); offset += 8; break;
                case 6:
                case 10:
                case 127:
                case 255: value = null; break;
                case 11: _ = CString(data, ref offset); _ = CString(data, ref offset); value = null; break;
                case 13:
                case 14: value = String(data, ref offset); break;
                case 16: Require(data, offset, 4); value = BinaryPrimitives.ReadInt32LittleEndian(data[offset..]); offset += 4; break;
                case 18: Require(data, offset, 8); value = BinaryPrimitives.ReadInt64LittleEndian(data[offset..]); offset += 8; break;
                case 19: Require(data, offset, 16); value = new Opaque(type, data.Slice(offset, 16).ToArray()); offset += 16; break;
                default: throw new InvalidDataException();
            }
            if (!fields.TryAdd(key, value)) throw new InvalidDataException();
        }
        if (offset != length - 1) throw new InvalidDataException();
        return fields;
    }

    internal static byte[] Encode(Dictionary<string, object?> fields)
    {
        using var stream = new MemoryStream(); using var writer = new BinaryWriter(stream, Utf8, true);
        writer.Write(0);
        foreach (var (key, value) in fields)
        {
            var type = value switch
            {
                null => 10, double => 1, string => 2, Dictionary<string, object?> => 3,
                string[] => 4, Binary => 5, bool => 8, int => 16, long => 18,
                _ => throw new InvalidDataException(),
            };
            writer.Write((byte)type); writer.Write(Utf8.GetBytes(key)); writer.Write((byte)0);
            switch (value)
            {
                case double number: writer.Write(number); break;
                case string text: var bytes = Utf8.GetBytes(text); writer.Write(bytes.Length + 1); writer.Write(bytes); writer.Write((byte)0); break;
                case Dictionary<string, object?> document: writer.Write(Encode(document)); break;
                case string[] array: writer.Write(Encode(array.Select((x, i) => (x, i)).ToDictionary(x => x.i.ToString(System.Globalization.CultureInfo.InvariantCulture), x => (object?)x.x))); break;
                case Binary binary: writer.Write(binary.Data.Length); writer.Write(binary.Subtype); writer.Write(binary.Data); break;
                case bool boolean: writer.Write(boolean); break;
                case int integer: writer.Write(integer); break;
                case long integer: writer.Write(integer); break;
            }
        }
        writer.Write((byte)0); writer.Flush();
        var output = stream.ToArray(); BinaryPrimitives.WriteInt32LittleEndian(output, output.Length); return output;
    }

    internal static string CString(ReadOnlySpan<byte> data, ref int offset)
    {
        if ((uint)offset >= (uint)data.Length) throw new InvalidDataException();
        var end = data[offset..].IndexOf((byte)0);
        if (end < 0) throw new InvalidDataException();
        var result = Utf8.GetString(data.Slice(offset, end)); offset += end + 1; return result;
    }

    private static string String(ReadOnlySpan<byte> data, ref int offset)
    {
        Require(data, offset, 4); var length = BinaryPrimitives.ReadInt32LittleEndian(data[offset..]); offset += 4;
        if (length < 1) throw new InvalidDataException(); Require(data, offset, length);
        if (data[offset + length - 1] != 0) throw new InvalidDataException();
        var result = Utf8.GetString(data.Slice(offset, length - 1)); offset += length; return result;
    }

    private static void Require(ReadOnlySpan<byte> data, int offset, int count)
    {
        // 最后一个文档终止字节不能被字段内容吞掉。
        if (count < 0 || offset < 0 || offset > data.Length - 1 || count > data.Length - 1 - offset) throw new InvalidDataException();
    }
}
