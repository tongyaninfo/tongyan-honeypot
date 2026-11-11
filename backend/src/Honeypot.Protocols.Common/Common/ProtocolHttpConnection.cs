using System.Globalization;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Honeypot.Protocol.Abstractions.Models;
using Honeypot.Protocol.Abstractions.Service;

namespace Honeypot.Protocols.Common;

/// <summary>复用运行时受限流的 HTTP/1.x 连接，不另开端口。整帧有界并共享截止时间。</summary>
public sealed class ProtocolHttpConnection : IAsyncDisposable
{
    private readonly IHoneypotSession _session;
    private readonly ServiceProfile _profile;
    private Stream? _stream;
    private SslStream? _tls;
    private X509Certificate2? _certificate;
    private int _prefix = -1;
    private long _bytes;
    public ProtocolHttpConnection(IHoneypotSession session, ServiceProfile profile) { _session = session; _profile = profile; }

    public async ValueTask<bool> InitializeAsync(CancellationToken ct)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(_profile.HandshakeTimeout);
        var first = new byte[1];
        if (await _session.ReadAsync(first, timeout.Token) == 0) return false;
        _bytes++;
        if (first[0] == 0x16)
        {
            if (_session is not IRawStreamHoneypotSession raw) throw new InvalidDataException("TLS stream unavailable");
            _certificate = ProtocolTls.CreateServerCertificate(ProtocolFingerprint.HostName(_profile));
            _tls = new SslStream(new PrefixStream(raw.RawStream, first[0]), leaveInnerStreamOpen: true);
            await _tls.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
            {
                ServerCertificate = _certificate, EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                ApplicationProtocols = [SslApplicationProtocol.Http11],
            }, timeout.Token);
            _stream = _tls;
        }
        else _prefix = first[0];
        return true;
    }

    public async ValueTask<ProtocolHttpRequest?> ReadAsync(CancellationToken ct)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(_profile.IdleTimeout);
        var token = timeout.Token;
        var consumed = 0;
        async ValueTask<string?> LineAsync(bool allowEof = false)
        {
            using var line = new MemoryStream();
            while (true)
            {
                var value = await ByteAsync(token);
                if (value < 0)
                {
                    if (allowEof && line.Length == 0) return null;
                    throw new InvalidDataException("Truncated HTTP line");
                }
                if (++consumed > _profile.MaxFrameBytes) throw new InvalidDataException("HTTP frame limit");
                if (value == 10)
                {
                    var bytes = line.ToArray();
                    if (bytes.Length == 0 || bytes[^1] != 13) throw new InvalidDataException("Invalid HTTP line ending");
                    return Encoding.ASCII.GetString(bytes, 0, bytes.Length - 1);
                }
                if (value == 0 || value > 127) throw new InvalidDataException("Invalid HTTP header");
                line.WriteByte((byte)value);
            }
        }
        var requestLine = await LineAsync(true);
        if (requestLine is null) return null;
        var parts = requestLine.Split(' ');
        if (parts.Length != 3 || parts[0].Length == 0 || !parts[1].StartsWith('/') || parts[1].Contains('#') ||
            parts[1].Any(c => c <= 32 || c == 127) ||
            !parts[0].All(c => c is >= 'A' and <= 'Z') || parts[2] is not ("HTTP/1.1" or "HTTP/1.0"))
            throw new InvalidDataException("Invalid HTTP request line");
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        for (var count = 0; ; count++)
        {
            var line = (await LineAsync())!;
            if (line.Length == 0) break;
            if (count >= 100) throw new InvalidDataException("HTTP header limit");
            var colon = line.IndexOf(':');
            if (colon <= 0 || line[..colon].Any(c => !char.IsAsciiLetterOrDigit(c) && c != '-'))
                throw new InvalidDataException("Invalid HTTP header name");
            var name = line[..colon]; var value = line[(colon + 1)..].Trim();
            if (value.Any(c => c < 32 && c != '\t')) throw new InvalidDataException("Invalid HTTP header value");
            // 不接受含糊的认证或消息长度头，防止 request smuggling 和采证串线。
            if (!headers.TryAdd(name, value)) throw new InvalidDataException("Duplicate HTTP header");
        }
        if (parts[2] == "HTTP/1.1" && !headers.ContainsKey("Host")) throw new InvalidDataException("Missing HTTP host");
        var chunked = headers.TryGetValue("Transfer-Encoding", out var encoding);
        if (chunked && (!string.Equals(encoding, "chunked", StringComparison.OrdinalIgnoreCase) || headers.ContainsKey("Content-Length")))
            throw new InvalidDataException("Unsupported HTTP framing");
        var length = 0;
        if (headers.TryGetValue("Content-Length", out var lengthText) &&
            (!int.TryParse(lengthText, NumberStyles.None, CultureInfo.InvariantCulture, out length) || length > _profile.MaxFrameBytes - consumed))
            throw new InvalidDataException("HTTP body limit");
        if (headers.TryGetValue("Expect", out var expect))
        {
            if (!expect.Equals("100-continue", StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("Unsupported expectation");
            await WriteBytesAsync(Encoding.ASCII.GetBytes("HTTP/1.1 100 Continue\r\n\r\n"), token);
        }
        using var body = new MemoryStream();
        async ValueTask ReadBodyAsync(int size)
        {
            if (size < 0 || size > _profile.MaxFrameBytes - consumed) throw new InvalidDataException("HTTP body limit");
            for (var i = 0; i < size; i++)
            {
                var value = await ByteAsync(token);
                if (value < 0) throw new InvalidDataException("Truncated HTTP body");
                consumed++; body.WriteByte((byte)value);
            }
        }
        if (chunked)
        {
            while (true)
            {
                var chunk = (await LineAsync())!.Split(';', 2)[0];
                if (!int.TryParse(chunk, NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out var size) || size < 0)
                    throw new InvalidDataException("Invalid HTTP chunk");
                if (size == 0)
                {
                    // 认证字段只接受初始头；不允许 trailer 注入另一套身份。
                    if (await LineAsync() != "") throw new InvalidDataException("Unsupported HTTP trailer");
                    break;
                }
                await ReadBodyAsync(size);
                if (await LineAsync() != "") throw new InvalidDataException("Invalid HTTP chunk ending");
            }
        }
        else await ReadBodyAsync(length);
        return new(parts[0], parts[1], parts[2], headers, body.ToArray());
    }

    public async ValueTask WriteAsync(ProtocolHttpResponse response, bool head, bool close, CancellationToken ct)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(_profile.IdleTimeout);
        var token = deadline.Token;
        var body = Encoding.UTF8.GetBytes(response.Body);
        var reason = response.Status switch { 200 => "OK", 204 => "No Content", 400 => "Bad Request", 401 => "Unauthorized", 404 => "Not Found", _ => "Error" };
        var header = new StringBuilder($"HTTP/1.1 {response.Status} {reason}\r\nDate: {DateTimeOffset.UtcNow:R}\r\nContent-Type: application/json; charset=utf-8\r\n");
        // 204 按 HTTP 规范没有消息体，也不得发送 Content-Length。
        if (response.Status != 204) header.Append($"Content-Length: {body.Length}\r\n");
        header.Append($"Connection: {(close ? "close" : "keep-alive")}\r\n");
        foreach (var field in response.Headers)
        {
            if (field.Key.Contains('\r') || field.Key.Contains('\n') || field.Value.Contains('\r') || field.Value.Contains('\n'))
                throw new InvalidDataException("Invalid response header");
            header.Append(field.Key).Append(": ").Append(field.Value).Append("\r\n");
        }
        header.Append("\r\n");
        await WriteBytesAsync(Encoding.ASCII.GetBytes(header.ToString()), token);
        if (!head && response.Status != 204 && body.Length > 0) await WriteBytesAsync(body, token);
    }

    private async ValueTask<int> ByteAsync(CancellationToken ct)
    {
        if (_prefix >= 0) { var b = _prefix; _prefix = -1; return b; }
        var buffer = new byte[1];
        var n = _stream is null ? await _session.ReadAsync(buffer, ct) : await _stream.ReadAsync(buffer, ct);
        if (n == 0) return -1;
        if (++_bytes > _profile.MaxSessionBytes) throw new InvalidDataException("HTTP session limit");
        return buffer[0];
    }
    private async ValueTask WriteBytesAsync(ReadOnlyMemory<byte> bytes, CancellationToken ct)
    {
        _bytes += bytes.Length;
        if (_bytes > _profile.MaxSessionBytes) throw new InvalidDataException("HTTP session limit");
        if (_stream is null) await _session.WriteAsync(bytes, ct);
        else await _stream.WriteAsync(bytes, ct);
    }
    public async ValueTask DisposeAsync()
    {
        if (_tls is not null) await _tls.DisposeAsync();
        _certificate?.Dispose();
    }

    private sealed class PrefixStream(Stream stream, byte prefix) : Stream
    {
        private bool _pending = true;
        public override bool CanRead => true; public override bool CanSeek => false; public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count)
        {
            if (_pending && count > 0) { buffer[offset] = prefix; _pending = false; return 1; }
            return stream.Read(buffer, offset, count);
        }
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default)
        {
            if (_pending && buffer.Length > 0) { buffer.Span[0] = prefix; _pending = false; return ValueTask.FromResult(1); }
            return stream.ReadAsync(buffer, ct);
        }
        public override void Write(byte[] buffer, int offset, int count) => stream.Write(buffer, offset, count);
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct = default) => stream.WriteAsync(buffer, ct);
        public override void Flush() => stream.Flush();
        public override Task FlushAsync(CancellationToken ct) => stream.FlushAsync(ct);
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
    }
}
