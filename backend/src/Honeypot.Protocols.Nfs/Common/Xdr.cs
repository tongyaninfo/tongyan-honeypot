using System.Buffers.Binary;
using System.Text;

namespace Honeypot.Protocols.Nfs.Common;

/// <summary>有界 XDR 读取；长度和填充先校验再分配，不信任调用方声明的数组大小。</summary>
internal sealed class XdrReader(byte[] data)
{
    private int _offset;
    public int Remaining => data.Length - _offset;
    public uint UInt()
    {
        Require(4); var value = BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(_offset)); _offset += 4; return value;
    }
    public ulong ULong() => ((ulong)UInt() << 32) | UInt();
    public byte[] Fixed(int length) { Require(length); var value = data.AsSpan(_offset, length).ToArray(); _offset += length; return value; }
    public byte[] Opaque(int maximum)
    {
        var length = UInt();
        if (length > maximum || length > Remaining) throw new InvalidDataException("Invalid XDR opaque length.");
        var value = Fixed((int)length); Fixed((4 - (int)length % 4) % 4); return value;
    }
    public string Text(int maximum) => new UTF8Encoding(false, true).GetString(Opaque(maximum));
    public uint[] Array(int maximum)
    {
        var count = UInt(); if (count > maximum || count > Remaining / 4) throw new InvalidDataException("Invalid XDR array.");
        var values = new uint[(int)count]; for (var i = 0; i < values.Length; i++) values[i] = UInt(); return values;
    }
    public void End() { if (Remaining != 0) throw new InvalidDataException("Trailing XDR data."); }
    private void Require(int length) { if (length < 0 || length > Remaining) throw new InvalidDataException("Truncated XDR message."); }
}

internal sealed class XdrWriter
{
    private readonly MemoryStream _stream = new();
    public void UInt(uint value) { Span<byte> bytes = stackalloc byte[4]; BinaryPrimitives.WriteUInt32BigEndian(bytes, value); _stream.Write(bytes); }
    public void ULong(ulong value) { UInt((uint)(value >> 32)); UInt((uint)value); }
    public void Fixed(byte[] value) => _stream.Write(value);
    public void Opaque(byte[] value) { UInt((uint)value.Length); Fixed(value); Fixed(new byte[(4 - value.Length % 4) % 4]); }
    public void Text(string value) => Opaque(Encoding.UTF8.GetBytes(value));
    public byte[] Bytes() => _stream.ToArray();
}
