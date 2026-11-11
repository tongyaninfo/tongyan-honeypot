using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Honeypot.Protocol.Abstractions.Models;
using Honeypot.Protocol.Abstractions.Service;
using Honeypot.Protocols.Common;

namespace Honeypot.Protocols.Oracle;

/// <summary>Oracle Net/TTC 普通密码认证拒绝端点；不创建真实 Oracle 会话，不解密依赖未知密码的认证材料。</summary>
public sealed class OracleAdapter : ProtocolAdapterBase
{
    public override ServiceAdapterDescriptor Descriptor { get; } = new()
    {
        AdapterKey = "oracle", DisplayName = "Oracle", SupportedFidelityLevels = ["L0", "L1", "L2", "L3"],
        SupportedClients = ["Oracle Thin / TTC password authentication"],
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
            var connect = await ReadPacketAsync(session, profile, false, ct);
            if (connect is null) return;
            if (connect.Length < 34 || connect[4] != 1) throw new InvalidDataException();
            var descriptorLength = BinaryPrimitives.ReadUInt16BigEndian(connect.AsSpan(24));
            var descriptorOffset = BinaryPrimitives.ReadUInt16BigEndian(connect.AsSpan(26));
            if (descriptorOffset < 34 || descriptorOffset > connect.Length || descriptorLength > profile.MaxFrameBytes) throw new InvalidDataException();
            byte[] descriptor;
            if (descriptorOffset + descriptorLength <= connect.Length) descriptor = connect.AsSpan(descriptorOffset, descriptorLength).ToArray();
            else
            {
                // 长连接描述符由 Thin 客户端放入独立 DATA 包，ACCEPT 前仍使用 16 位包长。
                var continuation = await ReadPacketAsync(session, profile, false, ct);
                if (continuation is null || continuation.Length < 10 || continuation[4] != 6 || continuation.Length - 10 != descriptorLength)
                    throw new InvalidDataException();
                descriptor = continuation[10..];
            }
            var connectDescriptor = Encoding.UTF8.GetString(descriptor);
            var service = ReadServiceName(connectDescriptor) ?? profile.OracleServiceName;
            var accept = new byte[28];
            BinaryPrimitives.WriteUInt16BigEndian(accept, 315);
            accept[14] = 4; // 未启用 Native Network Encryption；不宣告未实现的安全协商。
            BinaryPrimitives.WriteUInt32BigEndian(accept.AsSpan(24), 8192);
            await session.WriteAsync(Packet(2, accept, false), ct);
            await sink.AppendAsync(Event(context, "HandshakeReceived", "handshake", "observed", "Oracle Net connection accepted"), ct);

            var protocol = await ReadDataAsync(session, profile, ct);
            if (protocol is null) return;
            if (protocol.Length < 3 || protocol[0] != 1) throw new InvalidDataException();
            await session.WriteAsync(Data(ProtocolResponse()), ct);
            var types = await ReadDataAsync(session, profile, ct);
            if (types is null) return;
            if (types.Length < 5 || types[0] != 2) throw new InvalidDataException();
            await session.WriteAsync(Data([2, 0, 0]), ct);

            var phaseOne = await ReadDataAsync(session, profile, ct);
            if (phaseOne is null) return;
            var first = ParseAuthentication(phaseOne, 118);
            var verifier = Convert.ToHexString(RandomNumberGenerator.GetBytes(16));
            var serverKey = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
            var salt = Convert.ToHexString(RandomNumberGenerator.GetBytes(16));
            var challenge = new Dictionary<string, string>
            {
                ["AUTH_SESSKEY"] = serverKey, ["AUTH_VFR_DATA"] = verifier,
                ["AUTH_PBKDF2_VGEN_COUNT"] = "4096", ["AUTH_PBKDF2_CSK_SALT"] = salt, ["AUTH_PBKDF2_SDER_COUNT"] = "3",
            };
            await session.WriteAsync(Data(AuthenticationChallenge(challenge)), ct);
            var phaseTwo = await ReadDataAsync(session, profile, ct);
            if (phaseTwo is null) return;
            var second = ParseAuthentication(phaseTwo, 115);
            if (second.User != first.User || !second.Values.TryGetValue("AUTH_PASSWORD", out var encodedPassword) ||
                !second.Values.ContainsKey("AUTH_SESSKEY") || encodedPassword.Length == 0 ||
                encodedPassword.Length % 32 != 0 || !encodedPassword.All(Uri.IsHexDigit)) throw new InvalidDataException();
            await RecordAuthenticationAsync(sink, context, profile, second.User, "Oracle/O5LOGON/12C", "ORA-01017", 1,
                "Response", JsonSerializer.SerializeToUtf8Bytes(new
                {
                    username = second.User, password = (string?)null, serviceName = service,
                    challenge, authenticationParameters = second.Values,
                }), ct, database: service);
            await session.WriteAsync(Data(LoginFailure()), ct);
        }
        catch (AuthenticationRecordingException) { closeReason = SessionCloseReason.StorageDegraded; throw; }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            closeReason = SessionCloseReason.HandshakeTimeout;
            await sink.AppendAsync(Event(context, "HandshakeTimeout", "handshake", "timeout", "Oracle authentication deadline exceeded"), cancellationToken);
        }
        catch (Exception ex) when (ex is InvalidDataException or DecoderFallbackException or OverflowException)
        {
            closeReason = SessionCloseReason.ProtocolViolation;
            await sink.AppendAsync(Event(context, "ProtocolViolation", "handshake", "rejected", "Invalid Oracle Net/TTC authentication message"), cancellationToken);
        }
        catch (IOException) { closeReason = SessionCloseReason.ClientClosed; }
        catch (OperationCanceledException) { closeReason = SessionCloseReason.ListenerStopping; throw; }
        catch (Exception) { closeReason = SessionCloseReason.InternalError; throw; }
        finally { await session.CloseAsync(closeReason, CancellationToken.None); }
    }

    private static async Task<byte[]?> ReadPacketAsync(IHoneypotSession session, ServiceProfile p, bool fullSize, CancellationToken ct) =>
        await ReadFrameAsync(session, p.MaxFrameBytes, 8, h =>
        {
            var size = fullSize ? BinaryPrimitives.ReadUInt32BigEndian(h) : BinaryPrimitives.ReadUInt16BigEndian(h);
            if (size < 8 || size > p.MaxFrameBytes) throw new InvalidDataException();
            return checked((int)size);
        }, ct);

    private static async Task<byte[]?> ReadDataAsync(IHoneypotSession session, ServiceProfile p, CancellationToken ct)
    {
        using var data = new MemoryStream();
        // Oracle DATA 的 more-data 标志按消息重组，且累积长度同样受帧预算约束。
        for (var part = 0; part < 64; part++)
        {
            var packet = await ReadPacketAsync(session, p, true, ct);
            if (packet is null) return null;
            if (packet.Length < 10 || packet[4] != 6) throw new InvalidDataException();
            if (data.Length + packet.Length - 10 > p.MaxFrameBytes) throw new InvalidDataException();
            data.Write(packet, 10, packet.Length - 10);
            if ((BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(8)) & 0x20) == 0) return data.ToArray();
        }
        throw new InvalidDataException();
    }

    private static byte[] ProtocolResponse()
    {
        using var output = new MemoryStream();
        output.Write([1, 6, 0]);
        output.Write(Encoding.ASCII.GetBytes("Oracle Database 19c Enterprise Edition Release 19.0.0.0.0 - Production\0"));
        output.Write([0x69, 0x03, 0, 0, 0, 0, 11]); // AL32UTF8，零元素，FDO 长度。
        var fdo = new byte[11]; fdo[9] = 0x07; fdo[10] = 0xd0; output.Write(fdo); // AL16UTF16。
        var compile = new byte[64]; compile[7] = 13;
        WriteClr(output, compile); WriteClr(output, new byte[8]);
        return output.ToArray();
    }

    private static byte[] AuthenticationChallenge(Dictionary<string, string> values)
    {
        using var output = new MemoryStream();
        output.WriteByte(8); WriteNumber(output, (uint)values.Count);
        foreach (var (key, value) in values)
        {
            WriteString(output, key); WriteString(output, value);
            WriteNumber(output, key == "AUTH_VFR_DATA" ? 0x4815u : 0u);
        }
        output.Write([9, 0, 0]);
        return output.ToArray();
    }

    private static byte[] LoginFailure()
    {
        using var output = new MemoryStream();
        output.WriteByte(4);
        // TTC OER 的标量均使用紧凑整数；包含 rowid、批处理错误数组及扩展错误号。
        output.Write(new byte[28]);
        WriteNumber(output, 1017); WriteNumber(output, 0);
        WriteClr(output, Encoding.UTF8.GetBytes("ORA-01017: invalid username/password; logon denied\n"));
        return output.ToArray();
    }

    private static (string User, Dictionary<string, string> Values) ParseAuthentication(byte[] data, byte function)
    {
        var r = new TtcReader(data);
        if (r.Byte() != 3 || r.Byte() != function) throw new InvalidDataException();
        r.Byte(); // sequence
        var hasUser = r.Byte();
        var userLength = r.Number(); r.Number();
        if (r.Byte() != 1) throw new InvalidDataException();
        var count = r.Number();
        if (count > 64 || r.Byte() != 1 || r.Byte() != 1) throw new InvalidDataException();
        var user = hasUser == 1 ? r.Clr() : [];
        if (user.Length != userLength) throw new InvalidDataException();
        var fields = new Dictionary<string, string>(StringComparer.Ordinal);
        for (var i = 0; i < count; i++)
        {
            var key = r.String(); var value = r.String(); r.Number();
            if (!fields.TryAdd(key, value)) throw new InvalidDataException();
        }
        return (new UTF8Encoding(false, true).GetString(user), fields);
    }

    private static string? ReadServiceName(string descriptor)
    {
        foreach (var name in new[] { "SERVICE_NAME", "SID" })
        {
            var start = descriptor.IndexOf("(" + name + "=", StringComparison.OrdinalIgnoreCase);
            if (start < 0) continue;
            start += name.Length + 2;
            var end = descriptor.IndexOf(')', start);
            if (end > start) return descriptor[start..end].Trim();
        }
        return null;
    }
    private static byte[] Packet(byte type, byte[] body, bool fullSize)
    {
        var result = new byte[8 + body.Length];
        if (fullSize) BinaryPrimitives.WriteUInt32BigEndian(result, (uint)result.Length);
        else BinaryPrimitives.WriteUInt16BigEndian(result, checked((ushort)result.Length));
        result[4] = type; body.CopyTo(result, 8); return result;
    }
    private static byte[] Data(byte[] data) => Packet(6, [0, 0, .. data], true);
    private static void WriteNumber(Stream output, uint number)
    {
        if (number == 0) { output.WriteByte(0); return; }
        var bytes = new byte[4]; BinaryPrimitives.WriteUInt32BigEndian(bytes, number);
        var start = 0; while (bytes[start] == 0) start++;
        output.WriteByte((byte)(4 - start)); output.Write(bytes.AsSpan(start));
    }
    private static void WriteString(Stream output, string value)
    { var bytes = Encoding.UTF8.GetBytes(value); WriteNumber(output, (uint)bytes.Length); if (bytes.Length > 0) WriteClr(output, bytes); }
    private static void WriteClr(Stream output, byte[] bytes)
    {
        if (bytes.Length > 252) throw new InvalidDataException();
        output.WriteByte((byte)bytes.Length); output.Write(bytes);
    }
    private sealed class TtcReader(byte[] data)
    {
        private int _offset;
        public byte Byte() => _offset < data.Length ? data[_offset++] : throw new InvalidDataException();
        public uint Number()
        {
            var count = Byte(); if (count > 4) throw new InvalidDataException();
            uint result = 0; for (var i = 0; i < count; i++) result = (result << 8) | Byte(); return result;
        }
        public byte[] Clr()
        {
            var length = Byte();
            if (length == 0 || length == 255) return [];
            if (length != 254) return Read(length);
            using var output = new MemoryStream();
            while (true) { var chunk = Number(); if (chunk == 0) break; output.Write(Read(checked((int)chunk))); }
            return output.ToArray();
        }
        public string String()
        {
            var length = Number(); var bytes = length == 0 ? [] : Clr();
            if (bytes.Length != length) throw new InvalidDataException();
            return new UTF8Encoding(false, true).GetString(bytes);
        }
        private byte[] Read(int length)
        {
            if (length < 0 || length > data.Length - _offset) throw new InvalidDataException();
            var result = data.AsSpan(_offset, length).ToArray(); _offset += length; return result;
        }
    }
}
