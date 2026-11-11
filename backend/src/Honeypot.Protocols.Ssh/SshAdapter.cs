using System.Buffers.Binary;
using System.Net;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Honeypot.Protocol.Abstractions.Models;
using Honeypot.Protocol.Abstractions.Service;
using Honeypot.Protocols.Common;

namespace Honeypot.Protocols.Ssh;

/// <summary>
/// 最小但可被标准 OpenSSH 客户端识别的 SSH 服务端握手。
/// 只完成 identification、KEX、NEWKEYS 和 userauth；认证永远失败，
/// 认证材料进入证据仓库后不创建真实业务会话。
/// </summary>
public sealed class SshAdapter : ProtocolAdapterBase
{
    private const byte KexInit = 20;
    private const byte NewKeys = 21;
    private const byte DhInit = 30;
    private const byte DhReply = 31;
    private const byte ServiceRequest = 5;
    private const byte ServiceAccept = 6;
    private const byte UserAuthRequest = 50;
    private const byte UserAuthFailure = 51;

    private static readonly BigInteger Group14Prime = new BigInteger(
        // RFC 3526 MODP Group 14 (2048 bit)。客户端会校验 DH 参数，不能使用截断素数。
        Convert.FromHexString("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF"),
        isUnsigned: true,
        isBigEndian: true);
    private static readonly BigInteger Group14Generator = new(2);
    private static readonly RSA HostKey = RSA.Create(2048);

    public override ServiceAdapterDescriptor Descriptor => new()
    {
        AdapterKey = "ssh",
        DisplayName = "SSH",
        Version = "1",
        SupportedTransports = new[] { "tcp" },
        SupportedFidelityLevels = new[] { "L1", "L2", "L3" },
        SupportedClients = new[] { "ssh", "paramiko" },
    };

    public override async ValueTask HandleAsync(IHoneypotSession session, ProtocolSessionContext context, ServiceProfile profile, IInteractionEventSink sink, CancellationToken ct = default)
    {
        var closeReason = SessionCloseReason.AdapterCompleted;
        try { await HandleConnectionAsync(session, context, profile, sink, ct); }
        catch (AuthenticationRecordingException) { closeReason = SessionCloseReason.StorageDegraded; throw; }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            closeReason = SessionCloseReason.HandshakeTimeout;
            await sink.AppendAsync(Event(context, "ProtocolViolation", "authentication", "timeout", "SSH authentication timed out"), ct);
        }
        catch (Exception ex) when (ex is InvalidDataException or OverflowException or CryptographicException)
        {
            closeReason = SessionCloseReason.ProtocolViolation;
            // 认证字段和解密结果不得进入错误日志。
            await sink.AppendAsync(Event(context, "ProtocolViolation", "authentication", "malformed", "SSH packet rejected"), ct);
        }
        catch (OperationCanceledException) { closeReason = SessionCloseReason.ListenerStopping; throw; }
        catch (IOException) { closeReason = SessionCloseReason.ClientClosed; }
        catch (Exception) { closeReason = SessionCloseReason.InternalError; throw; }
        finally { await session.CloseAsync(closeReason, CancellationToken.None); }
    }

    private static async ValueTask HandleConnectionAsync(IHoneypotSession session, ProtocolSessionContext context,
        ServiceProfile profile, IInteractionEventSink sink, CancellationToken ct)
    {
        using var handshake = CancellationTokenSource.CreateLinkedTokenSource(ct);
        handshake.CancelAfter(profile.HandshakeTimeout);
        var token = handshake.Token;
        var serverId = $"SSH-2.0-{ProtocolFingerprint.Product(profile).Replace(' ', '_')}_{ProtocolFingerprint.Version(profile)}";
        var serverIdBytes = Encoding.ASCII.GetBytes(serverId + "\r\n");
        await session.WriteAsync(serverIdBytes, token);
        await sink.AppendAsync(Event(context, "BannerSent", "banner", "sent", $"bytes={serverIdBytes.Length}"), token);
        var clientId = await ReadIdAsync(session, profile.HandshakeTimeout, token);
        if (clientId is null) return;
        if (!clientId.StartsWith("SSH-2.0-", StringComparison.Ordinal) && !clientId.StartsWith("SSH-1.99-", StringComparison.Ordinal)) throw new InvalidDataException();
        await sink.AppendAsync(Event(context, "HandshakeReceived", "identification", "observed", clientId, 1), token);
        var serverKex = BuildKexInit();
        await WritePlainAsync(session, serverKex, token);
        uint clientSequence = 0;
        uint serverSequence = 1;
        async ValueTask<byte[]> ReadExpected(byte expected)
        {
            for (var i = 0; i < 8; i++)
            {
                var packet = await ReadPlainAsync(session, profile, token);
                if (packet is null) throw new InvalidDataException();
                clientSequence++;
                if (packet.Value.Payload.Length == 0) throw new InvalidDataException();
                if (packet.Value.Payload[0] is 2 or 4) continue;
                if (packet.Value.Payload[0] != expected) throw new InvalidDataException();
                return packet.Value.Payload;
            }
            throw new InvalidDataException();
        }
        var clientKex = await ReadExpected(KexInit);
        var discardGuess = ValidateKex(clientKex);
        if (discardGuess)
        {
            if (await ReadPlainAsync(session, profile, token) is null) throw new InvalidDataException();
            clientSequence++;
        }
        var dh = await ReadExpected(DhInit);
        var dhReader = new SshReader(dh.AsSpan(1));
        var e = dhReader.ReadMpint();
        if (dhReader.Remaining != 0 || e <= 1 || e >= Group14Prime - 1) throw new InvalidDataException();
        var x = RandomBigInteger(Group14Prime - 2) + 1;
        var f = BigInteger.ModPow(Group14Generator, x, Group14Prime);
        var shared = BigInteger.ModPow(e, x, Group14Prime);
        var hostKey = HostKeyBlob();
        var hash = ExchangeHash(clientId, serverId, clientKex, serverKex, hostKey, e, f, shared);
        var reply = new SshWriter();
        reply.Byte(DhReply); reply.String(hostKey); reply.Mpint(f); reply.String(Signature(hash));
        await WritePlainAsync(session, reply.Bytes(), token); serverSequence++;
        await WritePlainAsync(session, new[] { NewKeys }, token); serverSequence++;
        await ReadExpected(NewKeys);
        handshake.CancelAfter(Timeout.InfiniteTimeSpan);
        using var crypto = SshCrypto.Create(shared, hash);
        using var authDeadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        authDeadline.CancelAfter(profile.IdleTimeout);
        token = authDeadline.Token;
        var attempts = 0;
        var serviceAccepted = false;
        string? interactiveUser = null;
        byte[]? interactiveRequest = null;
        var maximum = Math.Clamp(profile.MaxAuthenticationAttempts, 1, 100);
        // none 和无签名公钥探测不消耗密码次数，但仍受总请求数和会话截止时间约束。
        for (var requestCount = 0; requestCount < maximum * 4 + 32 && attempts < maximum; requestCount++)
        {
            var payload = await ReadEncryptedAsync(session, crypto, profile, clientSequence++, token);
            if (payload is null) return;
            if (payload.Length == 0) throw new InvalidDataException();
            if (payload[0] == 1) return;
            if (payload[0] is 2 or 4) continue;
            if (payload[0] == ServiceRequest)
            {
                var service = new SshReader(payload.AsSpan(1));
                if (service.Text() != "ssh-userauth" || service.Remaining != 0 || serviceAccepted) throw new InvalidDataException();
                var accepted = new SshWriter(); accepted.Byte(ServiceAccept); accepted.String("ssh-userauth");
                await WriteEncryptedAsync(session, crypto, serverSequence++, accepted.Bytes(), token);
                serviceAccepted = true;
                continue;
            }
            if (!serviceAccepted) throw new InvalidDataException();
            if (payload[0] == 61)
            {
                if (interactiveRequest is null) throw new InvalidDataException();
                var responses = new SshReader(payload.AsSpan(1));
                if (responses.UInt32() != 1) throw new InvalidDataException();
                var password = responses.Text();
                if (responses.Remaining != 0) throw new InvalidDataException();
                attempts++;
                await RecordAuthenticationAsync(sink, context, profile, interactiveUser, "keyboard-interactive", "SSH_MSG_USERAUTH_FAILURE", attempts,
                    "Plaintext", JsonSerializer.SerializeToUtf8Bytes(new { username = interactiveUser, password,
                        request = Convert.ToBase64String(interactiveRequest), response = Convert.ToBase64String(payload) }), token);
                interactiveUser = null; interactiveRequest = null;
            }
            else if (payload[0] == UserAuthRequest)
            {
                if (interactiveRequest is not null) throw new InvalidDataException();
                var reader = new SshReader(payload.AsSpan(1));
                var username = reader.Text();
                if (reader.Text() != "ssh-connection") throw new InvalidDataException();
                var method = reader.Text();
                if (method == "none")
                {
                    if (reader.Remaining != 0) throw new InvalidDataException();
                    await sink.AppendAsync(Event(context, "AuthenticationMethodsRequested", "authentication", "rejected", "SSH authentication methods requested",
                        username: profile.RecordUsername ? username : null), token);
                }
                else if (method == "keyboard-interactive")
                {
                    reader.Text(); reader.Text();
                    if (reader.Remaining != 0) throw new InvalidDataException();
                    interactiveUser = username; interactiveRequest = payload;
                    var prompt = new SshWriter(); prompt.Byte(60); prompt.String(""); prompt.String(""); prompt.String("");
                    prompt.UInt32(1); prompt.String("Password: "); prompt.Bool(false);
                    await WriteEncryptedAsync(session, crypto, serverSequence++, prompt.Bytes(), token);
                    continue;
                }
                else
                {
                    string? password = null;
                    string? newPassword = null;
                    var materialType = "Response";
                    var isProbe = false;
                    if (method == "password")
                    {
                        var changeRequested = reader.Bool(); password = reader.Text();
                        if (changeRequested) newPassword = reader.Text();
                        if (reader.Remaining != 0) throw new InvalidDataException();
                        materialType = "Plaintext";
                    }
                    else if (method == "publickey")
                    {
                        isProbe = !reader.Bool(); reader.Text(); reader.String();
                        if (!isProbe) reader.String();
                        if (reader.Remaining != 0) throw new InvalidDataException();
                    }
                    if (!isProbe) attempts++;
                    await RecordAuthenticationAsync(sink, context, profile, username, method, "SSH_MSG_USERAUTH_FAILURE", attempts,
                        materialType, JsonSerializer.SerializeToUtf8Bytes(new { username, method, password, newPassword, isProbe,
                            request = Convert.ToBase64String(payload) }), token);
                }
            }
            else throw new InvalidDataException();
            var failure = new SshWriter(); failure.Byte(UserAuthFailure);
            failure.String("publickey,password,keyboard-interactive"); failure.Bool(false);
            await WriteEncryptedAsync(session, crypto, serverSequence++, failure.Bytes(), token);
        }
        var disconnect = new SshWriter(); disconnect.Byte(1); disconnect.UInt32(2);
        disconnect.String("Too many authentication failures"); disconnect.String("");
        await WriteEncryptedAsync(session, crypto, serverSequence, disconnect.Bytes(), token);
    }

    private static bool ValidateKex(byte[] payload)
    {
        if (payload.Length < 17) throw new InvalidDataException();
        var reader = new SshReader(payload.AsSpan(17));
        var algorithms = new string[10][];
        for (var i = 0; i < algorithms.Length; i++) algorithms[i] = reader.Text().Split(',');
        string[] required = ["diffie-hellman-group14-sha256", "rsa-sha2-256", "aes128-ctr", "aes128-ctr", "hmac-sha2-256", "hmac-sha2-256", "none", "none"];
        for (var i = 0; i < required.Length; i++) if (!algorithms[i].Contains(required[i], StringComparer.Ordinal)) throw new InvalidDataException();
        var follows = reader.Bool(); reader.UInt32();
        if (reader.Remaining != 0) throw new InvalidDataException();
        return follows && (algorithms[0][0] != required[0] || algorithms[1][0] != required[1]);
    }

    private static async ValueTask<string?> ReadIdAsync(IHoneypotSession session, TimeSpan timeout, CancellationToken ct)
    {
        var data = new List<byte>(128);
        var one = new byte[1];
        while (data.Count < 255)
        {
            var count = await ReadTimeoutAsync(session, one, timeout, ct);
            if (count <= 0) return null;
            data.Add(one[0]);
            if (one[0] != (byte)'\n') continue;
            var line = Encoding.ASCII.GetString(data.ToArray()).TrimEnd('\r', '\n');
            return line.StartsWith("SSH-", StringComparison.Ordinal) ? line : null;
        }
        return null;
    }

    private static byte[] BuildKexInit()
    {
        var writer = new SshWriter();
        writer.Byte(KexInit);
        writer.Bytes(RandomNumberGenerator.GetBytes(16));
        writer.NameList("diffie-hellman-group14-sha256");
        writer.NameList("rsa-sha2-256");
        writer.NameList("aes128-ctr");
        writer.NameList("aes128-ctr");
        writer.NameList("hmac-sha2-256");
        writer.NameList("hmac-sha2-256");
        writer.NameList("none");
        writer.NameList("none");
        writer.NameList(string.Empty);
        writer.NameList(string.Empty);
        writer.Bool(false);
        writer.UInt32(0);
        return writer.Bytes();
    }

    private static byte[] HostKeyBlob()
    {
        var p = HostKey.ExportParameters(false);
        var writer = new SshWriter();
        writer.String("ssh-rsa");
        writer.Mpint(new BigInteger(p.Exponent!, isUnsigned: true, isBigEndian: true));
        writer.Mpint(new BigInteger(p.Modulus!, isUnsigned: true, isBigEndian: true));
        return writer.Bytes();
    }

    private static byte[] Signature(byte[] hash)
    {
        // rsa-sha2-256 对交换哈希 H 作为消息再次执行 SHA-256，再做 PKCS#1 v1.5 签名。
        var signature = HostKey.SignData(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var writer = new SshWriter();
        writer.String("rsa-sha2-256");
        writer.String(signature);
        return writer.Bytes();
    }

    private static byte[] ExchangeHash(string clientId, string serverId, byte[] clientKex, byte[] serverKex, byte[] hostKey, BigInteger e, BigInteger f, BigInteger shared)
    {
        var writer = new SshWriter();
        writer.String(clientId);
        writer.String(serverId);
        writer.String(clientKex);
        writer.String(serverKex);
        writer.String(hostKey);
        writer.Mpint(e);
        writer.Mpint(f);
        writer.Mpint(shared);
        return SHA256.HashData(writer.Bytes());
    }

    private static BigInteger RandomBigInteger(BigInteger max)
    {
        var bytes = RandomNumberGenerator.GetBytes(max.GetByteCount(isUnsigned: true));
        return new BigInteger(bytes, isUnsigned: true, isBigEndian: true) % max;
    }

    private static async ValueTask<int> ReadTimeoutAsync(IHoneypotSession session, Memory<byte> buffer, TimeSpan timeout, CancellationToken ct)
    {
        using var source = CancellationTokenSource.CreateLinkedTokenSource(ct);
        source.CancelAfter(timeout);
        // 保留现有单次读取预算，但期限到达必须交由适配器记录超时，不能伪装成对端 EOF。
        return await session.ReadAsync(buffer, source.Token);
    }

    private static async ValueTask<bool> ReadSshExactAsync(IHoneypotSession session, Memory<byte> buffer, TimeSpan timeout, CancellationToken ct)
    {
        var offset = 0;
        while (offset < buffer.Length)
        {
            var count = await ReadTimeoutAsync(session, buffer[offset..], timeout, ct);
            if (count <= 0) return false;
            offset += count;
        }
        return true;
    }

    private static async ValueTask WritePlainAsync(IHoneypotSession session, byte[] payload, CancellationToken ct) => await session.WriteAsync(Packet(payload, 8), ct);

    private static async ValueTask<PlainPacket?> ReadPlainAsync(IHoneypotSession session, ServiceProfile profile, CancellationToken ct)
    {
        var header = new byte[4];
        if (!await ReadSshExactAsync(session, header, profile.HandshakeTimeout, ct)) return null;
        var length = BinaryPrimitives.ReadUInt32BigEndian(header);
        if (length < 12 || length > profile.MaxFrameBytes || (length + 4) % 8 != 0) throw new InvalidDataException();
        var body = new byte[length];
        if (!await ReadSshExactAsync(session, body, profile.HandshakeTimeout, ct)) return null;
        var padding = body[0];
        if (padding < 4 || padding + 1 >= body.Length) throw new InvalidDataException();
        return new PlainPacket(body.AsSpan(1, checked((int)length - padding - 1)).ToArray(), 0);
    }

    private static async ValueTask<byte[]?> ReadEncryptedAsync(IHoneypotSession session, SshCrypto crypto, ServiceProfile profile, uint sequence, CancellationToken ct)
    {
        var firstEncrypted = new byte[16];
        if (!await ReadSshExactAsync(session, firstEncrypted, profile.HandshakeTimeout, ct)) return null;
        var first = crypto.Decrypt(firstEncrypted);
        var packetLength = BinaryPrimitives.ReadUInt32BigEndian(first.AsSpan(0, 4));
        if (packetLength < 12 || packetLength > profile.MaxFrameBytes || (packetLength + 4) % 16 != 0) throw new InvalidDataException();
        var encryptedBody = checked((int)((packetLength + 4 + 15) / 16 * 16) - 16);
        var rest = new byte[encryptedBody + 32];
        if (!await ReadSshExactAsync(session, rest, profile.HandshakeTimeout, ct)) return null;
        var plainRest = crypto.Decrypt(rest.AsSpan(0, encryptedBody).ToArray());
        var plain = new byte[16 + encryptedBody];
        first.CopyTo(plain, 0);
        plainRest.CopyTo(plain, 16);
        var padding = plain[4];
        if (padding < 4 || packetLength < padding + 1)
        {
            return null;
        }

        var payloadLength = checked((int)packetLength - padding - 1);
        // MAC 输入为 sequence number || 完整明文包（4-byte length + packet body）。
        var macInput = new byte[8 + packetLength];
        BinaryPrimitives.WriteUInt32BigEndian(macInput.AsSpan(0, 4), sequence);
        plain.CopyTo(macInput, 4);
        var receivedMac = rest.AsSpan(encryptedBody, 32);
        if (!CryptographicOperations.FixedTimeEquals(crypto.ReceiveMac(macInput), receivedMac))
        {
            return null;
        }

        return plain.AsSpan(5, payloadLength).ToArray();
    }

    private static async ValueTask WriteEncryptedAsync(IHoneypotSession session, SshCrypto crypto, uint sequence, byte[] payload, CancellationToken ct)
    {
        var packet = Packet(payload, 16);
        var macInput = new byte[4 + packet.Length];
        BinaryPrimitives.WriteUInt32BigEndian(macInput.AsSpan(0, 4), sequence);
        packet.CopyTo(macInput, 4);
        var mac = crypto.SendMac(macInput);
        var encrypted = crypto.Encrypt(packet);
        await session.WriteAsync(encrypted.Concat(mac).ToArray(), ct);
    }

    private static byte[] Packet(byte[] payload, int blockSize)
    {
        var padding = blockSize - ((payload.Length + 5) % blockSize);
        if (padding < 4) padding += blockSize;
        var length = payload.Length + padding + 1;
        var packet = new byte[4 + length];
        BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(0, 4), (uint)length);
        packet[4] = (byte)padding;
        payload.CopyTo(packet, 5);
        RandomNumberGenerator.Fill(packet.AsSpan(5 + payload.Length, padding));
        return packet;
    }

    private readonly record struct PlainPacket(byte[] Payload, uint Sequence);

    private sealed class SshWriter
    {
        private readonly MemoryStream _stream = new();
        public byte[] Bytes() => _stream.ToArray();
        public void Byte(byte value) => _stream.WriteByte(value);
        public void Bool(bool value) => Byte(value ? (byte)1 : (byte)0);
        public void Bytes(ReadOnlySpan<byte> value) => _stream.Write(value);
        public void UInt32(uint value) { Span<byte> buffer = stackalloc byte[4]; BinaryPrimitives.WriteUInt32BigEndian(buffer, value); _stream.Write(buffer); }
        public void String(string value) => String(Encoding.ASCII.GetBytes(value));
        public void String(ReadOnlySpan<byte> value) { UInt32((uint)value.Length); _stream.Write(value); }
        public void NameList(string value) => String(value);
        public void Mpint(BigInteger value)
        {
            var bytes = value.ToByteArray(isUnsigned: true, isBigEndian: true);
            if (bytes.Length > 0 && (bytes[0] & 0x80) != 0) bytes = new byte[] { 0 }.Concat(bytes).ToArray();
            String(bytes);
        }
    }

    private ref struct SshReader
    {
        private readonly ReadOnlySpan<byte> _data;
        private int _offset;
        public SshReader(ReadOnlySpan<byte> data) { _data = data; _offset = 0; }
        public int Remaining => _data.Length - _offset;
        public byte Byte() => _offset < _data.Length ? _data[_offset++] : throw new InvalidDataException();
        public bool Bool() => Byte() != 0;
        public uint UInt32() { if (Remaining < 4) throw new InvalidDataException(); var v = BinaryPrimitives.ReadUInt32BigEndian(_data.Slice(_offset, 4)); _offset += 4; return v; }
        public byte[] String() { var unsignedLength = UInt32(); if (unsignedLength > int.MaxValue) throw new InvalidDataException(); var length = (int)unsignedLength; if (length > Remaining) throw new InvalidDataException(); var bytes = _data.Slice(_offset, length).ToArray(); _offset += length; return bytes; }
        public string Text() => Encoding.UTF8.GetString(String());
        public BigInteger ReadMpint() { var bytes = String(); return bytes.Length == 0 ? BigInteger.Zero : new BigInteger(bytes, isUnsigned: false, isBigEndian: true); }
    }

    private sealed class SshCrypto : IDisposable
    {
        private readonly DirectionCrypto _receive;
        private readonly DirectionCrypto _send;

        private SshCrypto(DirectionCrypto receive, DirectionCrypto send)
        {
            _receive = receive;
            _send = send;
        }

        public static SshCrypto Create(BigInteger shared, byte[] hash)
        {
            // RFC 4253 要求 K 以 SSH mpint（含长度和正数前导零）参与 KDF。
            var keyWriter = new SshWriter();
            keyWriter.Mpint(shared);
            var k = keyWriter.Bytes();
            return new SshCrypto(
                new DirectionCrypto(Derive(k, hash, 'A')[..16], Derive(k, hash, 'C')[..16], Derive(k, hash, 'E')),
                new DirectionCrypto(Derive(k, hash, 'B')[..16], Derive(k, hash, 'D')[..16], Derive(k, hash, 'F')));
        }

        public void Dispose() { _receive.Dispose(); _send.Dispose(); }

        public byte[] Decrypt(byte[] input) => _receive.Transform(input);
        public byte[] Encrypt(byte[] input) => _send.Transform(input);
        public byte[] ReceiveMac(byte[] input) => _receive.Mac(input);
        public byte[] SendMac(byte[] input) => _send.Mac(input);

        private sealed class DirectionCrypto : IDisposable
        {
            private readonly byte[] _macKey;
            private readonly Aes _aes;
            private readonly ICryptoTransform _encryptor;
            private readonly byte[] _counter;

            public DirectionCrypto(byte[] iv, byte[] key, byte[] macKey)
            {
                _macKey = macKey;
                _counter = iv;
                _aes = Aes.Create();
                _aes.Mode = CipherMode.ECB;
                _aes.Padding = PaddingMode.None;
                _aes.Key = key;
                _encryptor = _aes.CreateEncryptor();
            }

            public void Dispose() { _encryptor.Dispose(); _aes.Dispose(); CryptographicOperations.ZeroMemory(_macKey); CryptographicOperations.ZeroMemory(_counter); }

            public byte[] Transform(byte[] input)
            {
                var output = new byte[input.Length];
                for (var offset = 0; offset < input.Length; offset += 16)
                {
                    var keyStream = new byte[16];
                    _encryptor.TransformBlock(_counter, 0, 16, keyStream, 0);
                    var count = Math.Min(16, input.Length - offset);
                    for (var i = 0; i < count; i++) output[offset + i] = (byte)(input[offset + i] ^ keyStream[i]);
                    for (var i = _counter.Length - 1; i >= 0; i--) if (++_counter[i] != 0) break;
                }
                return output;
            }

            public byte[] Mac(byte[] input)
            {
                using var hmac = new HMACSHA256(_macKey);
                return hmac.ComputeHash(input);
            }
        }

        private static byte[] Derive(byte[] k, byte[] h, char letter) => SHA256.HashData(k.Concat(h).Append((byte)letter).Concat(h).ToArray());
    }
}
