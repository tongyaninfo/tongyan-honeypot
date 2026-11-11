using System.Buffers.Binary;
using Honeypot.Protocol.Abstractions.Service;
using Honeypot.Protocols.MsSql.Models;

namespace Honeypot.Protocols.MsSql.Common;

/// <summary>TDS 消息按 EOM 重组；限制单包和完整消息，拒绝混合类型及失序分片。</summary>
internal static class TdsTransport
{
    public static async ValueTask<(byte Type, byte[] Payload)> ReadMessageAsync(Stream stream, int maximum, CancellationToken ct)
    {
        using var message = new MemoryStream();
        var header = new byte[8];
        byte? type = null;
        byte? lastPacket = null;
        do
        {
            await stream.ReadExactlyAsync(header, ct);
            var length = BinaryPrimitives.ReadUInt16BigEndian(header.AsSpan(2));
            if (length > maximum || message.Length + length - 8 > maximum)
                throw new TdsResourceLimitException();
            if (length < 8 || header[1] > 1 || header[7] != 0 ||
                (type.HasValue && type.Value != header[0]) ||
                (lastPacket.HasValue && header[6] != unchecked((byte)(lastPacket.Value + 1))))
                throw new InvalidDataException("Invalid TDS message framing.");
            type ??= header[0];
            lastPacket = header[6];
            var payload = new byte[length - 8];
            await stream.ReadExactlyAsync(payload, ct);
            message.Write(payload);
            if (header[1] == 1) return (type.Value, message.ToArray());
            if (payload.Length == 0) throw new InvalidDataException("Empty TDS continuation packet.");
        } while (true);
    }

    public static async ValueTask WriteMessageAsync(Stream stream, byte type, ReadOnlyMemory<byte> payload, CancellationToken ct)
    {
        var offset = 0;
        byte packetId = 1;
        do
        {
            var count = Math.Min(4088, payload.Length - offset);
            var packet = new byte[count + 8];
            packet[0] = type;
            packet[1] = (byte)(offset + count == payload.Length ? 1 : 0);
            BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2), checked((ushort)packet.Length));
            packet[6] = packetId++;
            payload.Slice(offset, count).CopyTo(packet.AsMemory(8));
            await stream.WriteAsync(packet, ct);
            offset += count;
        } while (offset < payload.Length);
        await stream.FlushAsync(ct);
    }
}

/// <summary>统一经受控会话读写并累计双向字节，不绕过连接生命周期。</summary>
internal sealed class TdsSessionStream(IHoneypotSession session, long maximumBytes) : Stream
{
    private long _bytes;
    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => true;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
    public override void Flush() { }
    public override Task FlushAsync(CancellationToken ct) => Task.CompletedTask;
    public override int Read(byte[] buffer, int offset, int count) => ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();
    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default)
    {
        var count = await session.ReadAsync(buffer, ct);
        Charge(count);
        return count;
    }
    public override void Write(byte[] buffer, int offset, int count) => WriteAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();
    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct = default)
    {
        Charge(buffer.Length);
        await session.WriteAsync(buffer, ct);
    }
    private void Charge(int count)
    {
        if (Interlocked.Add(ref _bytes, count) > maximumBytes) throw new TdsResourceLimitException();
    }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
}

/// <summary>
/// TDS 7.x 仅将 TLS 握手记录封装到 PRELOGIN 包；握手完成后切换为原始 TLS 记录。
/// 每次只消耗当前包，避免越过 TLS 与 TDS 的切换边界。
/// </summary>
internal sealed class TdsTlsHandshakeStream(Stream inner, int maximum) : Stream
{
    private byte[] _pending = [];
    private int _offset;
    private bool _handshake = true;
    public void CompleteHandshake() => _handshake = false;
    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => true;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
    public override void Flush() => inner.Flush();
    public override Task FlushAsync(CancellationToken ct) => inner.FlushAsync(ct);
    public override int Read(byte[] buffer, int offset, int count) => ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();
    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default)
    {
        if (buffer.Length == 0) return 0;
        if (_offset == _pending.Length)
        {
            if (!_handshake) return await inner.ReadAsync(buffer, ct);
            var (type, payload) = await TdsTransport.ReadMessageAsync(inner, maximum, ct);
            if (type != 0x12 || payload.Length == 0) throw new InvalidDataException("Expected TDS TLS handshake.");
            _pending = payload;
            _offset = 0;
        }
        var count = Math.Min(buffer.Length, _pending.Length - _offset);
        _pending.AsMemory(_offset, count).CopyTo(buffer);
        _offset += count;
        return count;
    }
    public override void Write(byte[] buffer, int offset, int count) => WriteAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();
    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct = default)
    {
        if (_handshake) await TdsTransport.WriteMessageAsync(inner, 0x12, buffer, ct);
        else await inner.WriteAsync(buffer, ct);
    }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
}
