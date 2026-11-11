namespace Honeypot.Runtime.Common;

/// <summary>对普通协议读写与 TLS RawStream 共用总字节预算，TLS 升级不能绕过限制。</summary>
public sealed class SessionBudgetStream(Stream inner, long byteLimit) : Stream
{
    private long _transferred;
    private int _peerClosed;
    public bool LimitExceeded => Interlocked.Read(ref _transferred) > byteLimit;
    public bool PeerClosed => Volatile.Read(ref _peerClosed) == 1;
    public override bool CanRead => inner.CanRead;
    public override bool CanSeek => false;
    public override bool CanWrite => inner.CanWrite;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

    private void Charge(int count)
    {
        if (Interlocked.Add(ref _transferred, count) > byteLimit)
            throw new IOException("SESSION_BYTE_LIMIT_EXCEEDED");
    }

    private int ReadSize(int requested)
    {
        var remaining = byteLimit - Interlocked.Read(ref _transferred);
        if (remaining < 0) throw new IOException("SESSION_BYTE_LIMIT_EXCEEDED");
        // 多读一个字节即可判定超限，无须把客户端剩余的大报文全部读入内存。
        return remaining >= requested ? requested : (int)Math.Min(requested, remaining + 1);
    }

    public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));
    public override int Read(Span<byte> buffer)
    {
        var read = inner.Read(buffer[..ReadSize(buffer.Length)]);
        if (read == 0 && buffer.Length > 0) Interlocked.Exchange(ref _peerClosed, 1);
        Charge(read);
        return read;
    }
    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        var read = await inner.ReadAsync(buffer[..ReadSize(buffer.Length)], cancellationToken);
        if (read == 0 && buffer.Length > 0) Interlocked.Exchange(ref _peerClosed, 1);
        Charge(read);
        return read;
    }
    public override void Write(byte[] buffer, int offset, int count) => Write(buffer.AsSpan(offset, count));
    public override void Write(ReadOnlySpan<byte> buffer) { Charge(buffer.Length); inner.Write(buffer); }
    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        Charge(buffer.Length);
        return inner.WriteAsync(buffer, cancellationToken);
    }
    public override void Flush() => inner.Flush();
    public override Task FlushAsync(CancellationToken cancellationToken) => inner.FlushAsync(cancellationToken);
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    protected override void Dispose(bool disposing) { if (disposing) inner.Dispose(); base.Dispose(disposing); }
    public override ValueTask DisposeAsync() => inner.DisposeAsync();
}
