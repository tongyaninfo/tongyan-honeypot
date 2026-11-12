namespace Honeypot.Api.Common;

// 保留有限副本用于审计，不阻塞 Streamable HTTP 的刷新，也不接管网络流生命周期。
internal sealed class McpResponseCapture(Stream destination) : Stream
{
    private readonly MemoryStream capture = new();
    public long Written { get; private set; }
    public ReadOnlyMemory<byte> Body => capture.GetBuffer().AsMemory(0, (int)capture.Length);
    public override bool CanRead => false;
    public override bool CanSeek => false;
    public override bool CanWrite => destination.CanWrite;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Flush() => destination.Flush();
    public override Task FlushAsync(CancellationToken cancellationToken) => destination.FlushAsync(cancellationToken);
    public override void Write(byte[] buffer, int offset, int count)
    {
        Capture(buffer.AsSpan(offset, count));
        destination.Write(buffer, offset, count);
    }
    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        Capture(buffer.Span);
        return destination.WriteAsync(buffer, cancellationToken);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing) capture.Dispose();
        base.Dispose(disposing);
    }

    private void Capture(ReadOnlySpan<byte> bytes)
    {
        Written += bytes.Length;
        var count = Math.Min(bytes.Length, McpAuditPayload.MaxResponseBytes - (int)capture.Length);
        if (count > 0) capture.Write(bytes[..count]);
    }
}
