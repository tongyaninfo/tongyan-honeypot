using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Honeypot.Protocol.Abstractions.Models;
using Honeypot.Protocol.Abstractions.Service;
using Honeypot.Protocols.Common;

namespace Honeypot.Protocols.HBase;

/// <summary>HBase 2.x 原生 RPC/SASL 拒绝端点；不提供 RegionServer 或 HTTP 网关。</summary>
public sealed class HBaseAdapter : ProtocolAdapterBase
{
    public override ServiceAdapterDescriptor Descriptor { get; } = new()
    {
        AdapterKey = "hbase", DisplayName = "HBase",
        SupportedFidelityLevels = ["L0", "L1", "L2", "L3"],
        SupportedClients = ["HBase 2.x RPC / DIGEST-MD5 delegation token"],
    };

    public override async ValueTask HandleAsync(IHoneypotSession session, ProtocolSessionContext context,
        ServiceProfile profile, IInteractionEventSink sink, CancellationToken cancellationToken = default)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(profile.HandshakeTimeout);
        var ct = deadline.Token;
        var closeReason = SessionCloseReason.AdapterCompleted;
        try
        {
            var preamble = new byte[6];
            if (!await ReadExactAsync(session, preamble, ct)) return;
            if (!preamble.AsSpan(0, 4).SequenceEqual("HBas"u8) || preamble[4] != 0 || preamble[5] is not (80 or 81 or 82))
                throw new InvalidDataException();
            await sink.AppendAsync(Event(context, "HandshakeReceived", "handshake", "observed", "HBase RPC preamble received"), ct);

            if (preamble[5] == 80)
            {
                // 安全 HBase 不允许 SIMPLE 降级；没有密码提交，不制造认证证据。
                await sink.AppendAsync(Event(context, "AuthenticationRequired", "authentication", "rejected", "SASL authentication is required"), ct);
                await session.WriteAsync(SimpleAuthenticationFailure(), ct);
                return;
            }
            var initial = await ReadTokenAsync(session, profile, ct);
            if (initial is null) return;
            if (preamble[5] == 81)
            {
                // 没有 KDC/服务密钥不能验证或解密 Kerberos 票据，仅保存实际收到的材料。
                if (initial.Length == 0) throw new InvalidDataException();
                await RecordAuthenticationAsync(sink, context, profile, null, "Kerberos/GSSAPI", "SASL_AUTHENTICATION_FAILED", 1,
                    "Ticket", JsonSerializer.SerializeToUtf8Bytes(new { password = (string?)null, token = Convert.ToBase64String(initial) }), ct);
                await session.WriteAsync(Failure("javax.security.sasl.SaslException", "GSS initiate failed"), ct);
                return;
            }

            if (initial.Length != 0) throw new InvalidDataException();
            var nonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(24));
            var challenge = $"realm=\"default\",nonce=\"{nonce}\",qop=\"auth,auth-int,auth-conf\",charset=utf-8,algorithm=md5-sess,cipher=\"3des,rc4,des,rc4-56,rc4-40\"";
            await session.WriteAsync(Challenge(challenge), ct);
            var response = await ReadTokenAsync(session, profile, ct);
            if (response is null) return;
            var fields = ParseDirectives(new UTF8Encoding(false, true).GetString(response));
            if (!fields.TryGetValue("username", out var tokenIdentifier) || !fields.TryGetValue("nonce", out var receivedNonce) ||
                receivedNonce != nonce || !fields.TryGetValue("response", out var proof) || proof.Length != 32 ||
                !proof.All(Uri.IsHexDigit) || !fields.ContainsKey("cnonce") || !fields.ContainsKey("digest-uri"))
                throw new InvalidDataException();
            var username = ReadTokenUsername(tokenIdentifier);
            await RecordAuthenticationAsync(sink, context, profile, username, "SASL/DIGEST-MD5", "SASL_AUTHENTICATION_FAILED", 1,
                "Response", JsonSerializer.SerializeToUtf8Bytes(new
                {
                    username, password = (string?)null, tokenIdentifier,
                    challenge, authenticationResponse = Convert.ToBase64String(response), identityVerified = false,
                }), ct);
            await session.WriteAsync(Failure("org.apache.hadoop.security.token.SecretManager$InvalidToken", "Token authentication failed"), ct);
        }
        catch (AuthenticationRecordingException) { closeReason = SessionCloseReason.StorageDegraded; throw; }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            closeReason = SessionCloseReason.HandshakeTimeout;
            await sink.AppendAsync(Event(context, "HandshakeTimeout", "handshake", "timeout", "HBase authentication deadline exceeded"), cancellationToken);
        }
        catch (Exception ex) when (ex is InvalidDataException or DecoderFallbackException or FormatException or OverflowException)
        {
            closeReason = SessionCloseReason.ProtocolViolation;
            await sink.AppendAsync(Event(context, "ProtocolViolation", "handshake", "rejected", "Invalid HBase RPC/SASL message"), cancellationToken);
        }
        catch (IOException) { closeReason = SessionCloseReason.ClientClosed; }
        catch (OperationCanceledException) { closeReason = SessionCloseReason.ListenerStopping; throw; }
        catch (Exception) { closeReason = SessionCloseReason.InternalError; throw; }
        finally { await session.CloseAsync(closeReason, CancellationToken.None); }
    }

    private static async Task<byte[]?> ReadTokenAsync(IHoneypotSession session, ServiceProfile profile, CancellationToken ct)
    {
        var frame = await ReadFrameAsync(session, profile.MaxFrameBytes, 4,
            header =>
            {
                var size = BinaryPrimitives.ReadInt32BigEndian(header);
                if (size < 0 || size > profile.MaxFrameBytes - 4) throw new InvalidDataException();
                return size + 4;
            }, ct);
        return frame?[4..];
    }

    private static byte[] Challenge(string challenge)
    {
        var content = Encoding.UTF8.GetBytes(challenge);
        var result = new byte[8 + content.Length];
        // HBase SASL SUCCESS 是“本次挑战有效”，不是连接认证成功。
        BinaryPrimitives.WriteInt32BigEndian(result.AsSpan(4), content.Length);
        content.CopyTo(result, 8);
        return result;
    }

    private static byte[] Failure(string exceptionClass, string message)
    {
        var type = Encoding.UTF8.GetBytes(exceptionClass);
        var body = Encoding.UTF8.GetBytes(message);
        var result = new byte[12 + type.Length + body.Length];
        BinaryPrimitives.WriteInt32BigEndian(result, 1);
        BinaryPrimitives.WriteInt32BigEndian(result.AsSpan(4), type.Length);
        type.CopyTo(result, 8);
        BinaryPrimitives.WriteInt32BigEndian(result.AsSpan(8 + type.Length), body.Length);
        body.CopyTo(result, 12 + type.Length);
        return result;
    }

    private static byte[] SimpleAuthenticationFailure()
    {
        // SIMPLE 不进入 SASL，须使用 RPC ResponseHeader protobuf，不能写 SASL status 帧。
        using var exception = new MemoryStream();
        WriteProtobufBytes(exception, 1, Encoding.UTF8.GetBytes("org.apache.hadoop.hbase.security.AccessDeniedException"));
        WriteProtobufBytes(exception, 2, Encoding.UTF8.GetBytes("Authentication is required"));
        exception.Write([0x28, 1]);
        using var header = new MemoryStream();
        header.WriteByte(8); WriteVarint(header, uint.MaxValue);
        WriteProtobufBytes(header, 2, exception.ToArray());
        using var body = new MemoryStream(); WriteVarint(body, (uint)header.Length); body.Write(header.ToArray());
        var result = new byte[4 + body.Length];
        BinaryPrimitives.WriteInt32BigEndian(result, checked((int)body.Length)); body.ToArray().CopyTo(result, 4);
        return result;
    }

    private static void WriteProtobufBytes(Stream stream, int field, byte[] value)
    { WriteVarint(stream, (uint)(field * 8 + 2)); WriteVarint(stream, (uint)value.Length); stream.Write(value); }
    private static void WriteVarint(Stream stream, uint value)
    { while (value >= 128) { stream.WriteByte((byte)((value & 127) | 128)); value >>= 7; } stream.WriteByte((byte)value); }

    private static Dictionary<string, string> ParseDirectives(string text)
    {
        var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var offset = 0;
        while (offset < text.Length)
        {
            while (offset < text.Length && (char.IsWhiteSpace(text[offset]) || text[offset] == ',')) offset++;
            if (offset == text.Length) break;
            var start = offset;
            while (offset < text.Length && text[offset] != '=') offset++;
            if (offset == text.Length) throw new InvalidDataException();
            var key = text[start..offset++].Trim();
            var value = new StringBuilder();
            if (offset < text.Length && text[offset] == '"')
            {
                offset++;
                var closed = false;
                while (offset < text.Length)
                {
                    var c = text[offset++];
                    if (c == '"') { closed = true; break; }
                    if (c == '\\')
                    {
                        if (offset == text.Length) throw new InvalidDataException();
                        c = text[offset++];
                    }
                    value.Append(c);
                }
                if (!closed) throw new InvalidDataException();
                while (offset < text.Length && char.IsWhiteSpace(text[offset])) offset++;
                if (offset < text.Length && text[offset] != ',') throw new InvalidDataException();
            }
            else while (offset < text.Length && text[offset] != ',') value.Append(text[offset++]);
            if (key.Length == 0 || !fields.TryAdd(key, value.ToString().Trim()) || fields.Count > 32) throw new InvalidDataException();
        }
        return fields;
    }

    private static string? ReadTokenUsername(string encoded)
    {
        // TokenIdentifier 是长度前缀 protobuf。仅提取声明的用户名，不把未验证身份当作认证成功。
        byte[] data;
        try { data = Convert.FromBase64String(encoded); }
        catch (FormatException) { return null; }
        if (data.Length < 4 || BinaryPrimitives.ReadInt32BigEndian(data) != data.Length - 4) return null;
        var offset = 4;
        string? username = null;
        while (offset < data.Length)
        {
            var tag = Varint(data, ref offset);
            if ((tag & 7) == 0) { _ = Varint(data, ref offset); continue; }
            if ((tag & 7) != 2) return null;
            var length = checked((int)Varint(data, ref offset));
            if (length > data.Length - offset) throw new InvalidDataException();
            if ((tag >> 3) == 2) username = new UTF8Encoding(false, true).GetString(data, offset, length);
            offset += length;
        }
        return username;
    }

    private static ulong Varint(byte[] data, ref int offset)
    {
        ulong result = 0;
        for (var shift = 0; shift < 64 && offset < data.Length; shift += 7)
        {
            var value = data[offset++];
            result |= (ulong)(value & 127) << shift;
            if ((value & 128) == 0) return result;
        }
        throw new InvalidDataException();
    }
}
