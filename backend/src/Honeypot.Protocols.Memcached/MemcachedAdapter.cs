using System.Buffers.Binary;
using System.Text;
using System.Text.Json;
using Honeypot.Protocol.Abstractions.Models;
using Honeypot.Protocol.Abstractions.Service;
using Honeypot.Protocols.Common;

namespace Honeypot.Protocols.Memcached;

/// <summary>Memcached binary SASL PLAIN 认证；不提供缓存读写，原样关联客户端 opaque。</summary>
public sealed class MemcachedAdapter : ProtocolAdapterBase
{
    public override ServiceAdapterDescriptor Descriptor => new()
    {
        AdapterKey = "memcached", DisplayName = "Memcached", SupportedFidelityLevels = ["L1", "L2", "L3"],
        SupportedClients = ["binary SASL clients"],
    };

    public override async ValueTask HandleAsync(IHoneypotSession session, ProtocolSessionContext context,
        ServiceProfile profile, IInteractionEventSink sink, CancellationToken cancellationToken = default)
    {
        var close = SessionCloseReason.AdapterCompleted;
        var attempts = 0;
        var continuing = false;
        try
        {
            for (var requests = 0; requests < 128 && attempts < profile.MaxAuthenticationAttempts; requests++)
            {
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                timeout.CancelAfter(requests == 0 ? profile.HandshakeTimeout : profile.IdleTimeout);
                var ct = timeout.Token;
                var header = new byte[24];
                if (!await ReadExactAsync(session, header, ct)) break;
                var opcode = header[1];
                var keyLength = BinaryPrimitives.ReadUInt16BigEndian(header.AsSpan(2));
                var extrasLength = header[4];
                var length = BinaryPrimitives.ReadUInt32BigEndian(header.AsSpan(8));
                if (header[0] != 0x80 || header[5] != 0 || length > profile.MaxFrameBytes - 24 || keyLength + extrasLength > length)
                    throw new InvalidDataException();
                var body = new byte[length];
                if (!await ReadExactAsync(session, body, ct)) throw new EndOfStreamException();
                if (opcode == 0x20)
                {
                    if (body.Length != 0) throw new InvalidDataException();
                    await ReplyAsync(session, header, 0, "PLAIN", ct); continue;
                }
                if (opcode == 0x0b)
                { await ReplyAsync(session, header, 0, "1.6.32", ct); continue; }
                if (opcode == 0x07)
                { await ReplyAsync(session, header, 0, "", ct); break; }
                if (opcode is not (0x21 or 0x22))
                { await ReplyAsync(session, header, 0x20, "Auth failure", ct); continue; }
                if (extrasLength != 0) throw new InvalidDataException();
                var mechanism = Encoding.ASCII.GetString(body, 0, keyLength);
                // RFC 4422 机制名有固定字符集和长度；任意键字节不能成为普通事件中的方法文本。
                if (mechanism.Length is < 1 or > 20 || mechanism.Any(c => !(c is >= 'A' and <= 'Z' or >= '0' and <= '9' or '-' or '_')))
                    throw new InvalidDataException();
                var payload = body.AsMemory(keyLength).ToArray();
                if (opcode == 0x22 && !continuing) throw new InvalidDataException();
                if (mechanism == "PLAIN" && payload.Length == 0 && opcode == 0x21)
                { continuing = true; await ReplyAsync(session, header, 0x21, "", ct); continue; }
                continuing = false;
                string? username = null, password = null, authorizationId = null;
                var type = "Response";
                if (mechanism == "PLAIN")
                {
                    var first = Array.IndexOf(payload, (byte)0);
                    var second = first < 0 ? -1 : Array.IndexOf(payload, (byte)0, first + 1);
                    if (first < 0 || second < 0 || Array.IndexOf(payload, (byte)0, second + 1) >= 0)
                        throw new InvalidDataException();
                    var utf8 = new UTF8Encoding(false, true);
                    authorizationId = utf8.GetString(payload, 0, first);
                    username = utf8.GetString(payload, first + 1, second - first - 1);
                    password = utf8.GetString(payload, second + 1, payload.Length - second - 1);
                    type = "Plaintext";
                }
                await RecordAuthenticationAsync(sink, context, profile, username, mechanism == "PLAIN" ? "SASL PLAIN" : "SASL unsupported",
                    "0x0020", ++attempts, type, JsonSerializer.SerializeToUtf8Bytes(new
                    { protocol = "memcached", username, password, authorizationId, mechanism, response = Convert.ToBase64String(payload) }), ct);
                await ReplyAsync(session, header, 0x20, "Auth failure", ct);
            }
        }
        catch (AuthenticationRecordingException) { close = SessionCloseReason.StorageDegraded; }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) { close = SessionCloseReason.IdleTimeout; }
        catch (Exception ex) when (ex is InvalidDataException or DecoderFallbackException)
        {
            close = SessionCloseReason.ProtocolViolation;
            await sink.AppendAsync(Event(context, "ProtocolViolation", "sasl", "rejected", "Invalid Memcached binary request"), cancellationToken);
        }
        catch (IOException) { close = SessionCloseReason.ClientClosed; }
        catch (OperationCanceledException) { close = SessionCloseReason.ListenerStopping; throw; }
        catch (Exception) { close = SessionCloseReason.InternalError; throw; }
        finally { await session.CloseAsync(close, CancellationToken.None); }
    }

    private static ValueTask ReplyAsync(IHoneypotSession session, byte[] request, ushort status, string text, CancellationToken ct)
    {
        var body = Encoding.UTF8.GetBytes(text);
        var reply = new byte[24 + body.Length]; reply[0] = 0x81; reply[1] = request[1];
        BinaryPrimitives.WriteUInt16BigEndian(reply.AsSpan(6), status);
        BinaryPrimitives.WriteUInt32BigEndian(reply.AsSpan(8), (uint)body.Length);
        request.AsSpan(12, 4).CopyTo(reply.AsSpan(12)); body.CopyTo(reply, 24);
        return session.WriteAsync(reply, ct);
    }
}
