using System.Buffers.Binary;
using System.Net;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Honeypot.Protocol.Abstractions.Models;
using Honeypot.Protocol.Abstractions.Service;
using Honeypot.Protocols.Common;

namespace Honeypot.Protocols.MySql;

/// <summary>只完成 MySQL 认证交换；收到材料后始终返回 1045，不建立 SQL 会话。</summary>
public sealed class MySqlAdapter : ProtocolAdapterBase
{
    private const uint ConnectWithDatabase = 0x00000008;
    private const uint Protocol41 = 0x00000200;
    private const uint ClientSsl = 0x00000800;
    private const uint SecureConnection = 0x00008000;
    private const uint PluginAuth = 0x00080000;
    private const uint ConnectAttributes = 0x00100000;
    private const uint LengthEncodedAuth = 0x00200000;
    private static readonly UTF8Encoding Utf8 = new(false, true);

    public override ServiceAdapterDescriptor Descriptor => new()
    {
        AdapterKey = "mysql", DisplayName = "MySQL", Version = "1", SupportedTransports = ["tcp"],
        SupportedFidelityLevels = ["L1", "L2", "L3"], SupportedClients = ["mysql", "MySqlConnector"],
    };

    public override async ValueTask<AdapterValidationResult> ValidateAsync(ServiceProfile profile, CancellationToken cancellationToken = default)
    {
        var result = await base.ValidateAsync(profile, cancellationToken);
        if (!result.IsValid) return result;
        return profile.MySqlAuthenticationPlugin is "caching_sha2_password" or "mysql_native_password"
            ? result : AdapterValidationResult.Invalid("MYSQL_AUTH_PLUGIN_UNSUPPORTED", "unsupported MySQL authentication plugin");
    }

    public override async ValueTask HandleAsync(IHoneypotSession session, ProtocolSessionContext context,
        ServiceProfile profile, IInteractionEventSink sink, CancellationToken cancellationToken = default)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(profile.HandshakeTimeout);
        var ct = timeout.Token;
        SslStream? tls = null;
        var reason = SessionCloseReason.AdapterCompleted;
        Login? pendingLogin = null;
        byte[]? initialResponse = null, captureScramble = null, latestResponse = null;
        string? captureMethod = null;
        var recordingStarted = false;
        try
        {
            var wire = new PacketConnection(session, profile);
            var scramble = RandomNumberGenerator.GetBytes(20);
            // auth-plugin-data 以 NUL 结尾，挑战本身不能提前出现 NUL。
            for (var i = 0; i < scramble.Length; i++) if (scramble[i] == 0) scramble[i] = 1;
            captureScramble = scramble;
            var plugin = profile.MySqlAuthenticationPlugin;
            if (plugin is not ("caching_sha2_password" or "mysql_native_password"))
                throw new InvalidDataException();
            var supportsTls = session is IRawStreamHoneypotSession;
            await wire.WriteAsync(BuildHandshake(profile, scramble, plugin, supportsTls), ct);
            await sink.AppendAsync(Event(context, "BannerSent", "banner", "sent", "mysql HandshakeV10"), ct);
            var response = await wire.ReadAsync(ct);
            if (response.Length == 32 && (BinaryPrimitives.ReadUInt32LittleEndian(response) & ClientSsl) != 0)
            {
                if (!supportsTls || (BinaryPrimitives.ReadUInt32LittleEndian(response) & Protocol41) == 0)
                    throw new InvalidDataException();
                using var certificate = ProtocolTls.CreateServerCertificate(ProtocolFingerprint.HostName(profile));
                tls = new SslStream(((IRawStreamHoneypotSession)session).RawStream, leaveInnerStreamOpen: true);
                await tls.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
                {
                    ServerCertificate = certificate, EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                    ClientCertificateRequired = false,
                }, ct);
                wire.Stream = tls;
                response = await wire.ReadAsync(ct);
            }
            var login = ParseLogin(response);
            pendingLogin = login;
            initialResponse = response;
            if (tls is null && (login.Capabilities & ClientSsl) != 0) throw new InvalidDataException();
            var method = string.IsNullOrEmpty(login.Plugin) ? plugin : login.Plugin;
            captureMethod = method;
            byte[]? followup = null;
            string? password = null;
            var materialType = "Response";
            // 客户端报告了不同插件时，正常执行 AuthSwitchRequest，再按服务端人格收集认证。
            if (method != plugin)
            {
                await wire.WriteAsync(Join([0xfe], Encoding.ASCII.GetBytes(plugin + "\0"), scramble, [0]), ct);
                followup = await wire.ReadAsync(ct);
                latestResponse = followup;
                login = login with { AuthResponse = followup };
                method = plugin;
                pendingLogin = login;
                captureMethod = method;
            }
            if (method == "caching_sha2_password")
            {
                if (login.AuthResponse.Length == 0 || login.AuthResponse is [0])
                {
                    password = "";
                    materialType = "Plaintext";
                }
                else if (login.AuthResponse.Length == 32)
                {
                    // 0x04 请求 full authentication；没有任何认证成功包或业务会话。
                    await wire.WriteAsync([0x01, 0x04], ct);
                    followup = await wire.ReadAsync(ct);
                    latestResponse = followup;
                    if (tls is not null)
                    {
                        password = ReadPassword(followup);
                        materialType = "Plaintext";
                    }
                    else
                    {
                        using var rsa = RSA.Create(2048);
                        if (followup is [0x02])
                        {
                            await wire.WriteAsync(Join([0x01], Encoding.ASCII.GetBytes(rsa.ExportSubjectPublicKeyInfoPem()), [0]), ct);
                            followup = await wire.ReadAsync(ct);
                            latestResponse = followup;
                        }
                        // 非 TLS 的 full-auth 必须为 RSA-OAEP 密文，不接受明文降级。
                        materialType = "Ciphertext";
                        if (followup.Length == rsa.KeySize / 8)
                        {
                            byte[]? decoded = null;
                            try
                            {
                                decoded = rsa.Decrypt(followup, RSAEncryptionPadding.OaepSHA1);
                                for (var i = 0; i < decoded.Length; i++) decoded[i] ^= scramble[i % scramble.Length];
                                password = ReadPassword(decoded);
                                materialType = "Decrypted";
                            }
                            catch (CryptographicException) { /* 仍保存实际收到的密文并返回认证失败。 */ }
                            finally { if (decoded is not null) CryptographicOperations.ZeroMemory(decoded); }
                        }
                    }
                }
            }
            var evidence = JsonSerializer.SerializeToUtf8Bytes(new
            {
                username = login.Username, database = login.Database, method, password,
                scramble = Convert.ToBase64String(scramble),
                handshakeResponse = Convert.ToBase64String(response),
                authenticationResponse = Convert.ToBase64String(login.AuthResponse),
                fullAuthenticationResponse = followup is null ? null : Convert.ToBase64String(followup),
            });
            try
            {
                recordingStarted = true;
                await RecordAuthenticationAsync(sink, context, profile, login.Username, method, "1045", 1,
                    materialType, evidence, ct, database: login.Database);
            }
            finally { CryptographicOperations.ZeroMemory(evidence); }
            await wire.WriteAsync(BuildError(login.AuthResponse.Length != 0), ct);
        }
        catch (AuthenticationRecordingException) { reason = SessionCloseReason.StorageDegraded; throw; }
        catch (EndOfStreamException)
        {
            reason = SessionCloseReason.ClientClosed;
            await RecordIncompleteAsync("client-closed-before-full-auth");
        }
        catch (Exception ex) when (ex is InvalidDataException or DecoderFallbackException or AuthenticationException)
        {
            reason = SessionCloseReason.ProtocolViolation;
            await RecordIncompleteAsync("invalid-frame-before-full-auth");
            await sink.AppendAsync(Event(context, "ProtocolViolation", "authentication", "rejected", "invalid MySQL handshake or authentication frame"), cancellationToken);
        }
        catch (IOException)
        {
            reason = SessionCloseReason.ClientClosed;
            await RecordIncompleteAsync("transport-closed-before-full-auth");
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            reason = SessionCloseReason.HandshakeTimeout;
            await RecordIncompleteAsync("timeout-before-full-auth");
            await sink.AppendAsync(Event(context, "ProtocolViolation", "authentication", "timeout", "MySQL authentication timeout"), cancellationToken);
        }
        catch (OperationCanceledException) { reason = SessionCloseReason.ListenerStopping; throw; }
        catch (Exception) { reason = SessionCloseReason.InternalError; throw; }
        finally
        {
            try { if (tls is not null) await tls.DisposeAsync(); }
            finally { await session.CloseAsync(reason, CancellationToken.None); }
        }

        async ValueTask RecordIncompleteAsync(string stage)
        {
            if (pendingLogin is null || recordingStarted || cancellationToken.IsCancellationRequested) return;
            recordingStarted = true;
            // 认证时限已到也保留之前收到的身份/响应；独立短时限防止存证阻塞关闭。
            using var evidenceTimeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            evidenceTimeout.CancelAfter(TimeSpan.FromSeconds(3));
            var material = JsonSerializer.SerializeToUtf8Bytes(new
            {
                username = pendingLogin.Username, database = pendingLogin.Database, method = captureMethod, password = (string?)null, stage,
                scramble = captureScramble is null ? null : Convert.ToBase64String(captureScramble),
                handshakeResponse = initialResponse is null ? null : Convert.ToBase64String(initialResponse),
                authenticationResponse = Convert.ToBase64String(pendingLogin.AuthResponse),
                fullAuthenticationResponse = latestResponse is null ? null : Convert.ToBase64String(latestResponse),
            });
            try
            {
                await RecordAuthenticationAsync(sink, context, profile, pendingLogin.Username, captureMethod ?? "unknown", "1045", 1,
                    "Response", material, evidenceTimeout.Token, database: pendingLogin.Database);
            }
            finally { CryptographicOperations.ZeroMemory(material); }
        }
    }

    private static byte[] BuildHandshake(ServiceProfile profile, byte[] scramble, string plugin, bool tls)
    {
        var capabilities = 0x00000001u | 0x00000004u | ConnectWithDatabase | Protocol41 | 0x00002000u |
                           SecureConnection | PluginAuth | ConnectAttributes | LengthEncodedAuth | (tls ? ClientSsl : 0);
        using var stream = new MemoryStream();
        using var writer = new BinaryWriter(stream, Encoding.UTF8, true);
        writer.Write((byte)10);
        writer.Write(Encoding.ASCII.GetBytes($"{ProtocolFingerprint.Version(profile)}-{ProtocolFingerprint.Product(profile)}\0"));
        writer.Write(RandomNumberGenerator.GetInt32(1, int.MaxValue));
        writer.Write(scramble.AsSpan(0, 8)); writer.Write((byte)0);
        writer.Write((ushort)capabilities); writer.Write((byte)45); writer.Write((ushort)2);
        writer.Write((ushort)(capabilities >> 16)); writer.Write((byte)21); writer.Write(new byte[10]);
        writer.Write(scramble.AsSpan(8)); writer.Write((byte)0);
        writer.Write(Encoding.ASCII.GetBytes(plugin + "\0"));
        return stream.ToArray();
    }

    private sealed record Login(uint Capabilities, string Username, byte[] AuthResponse, string? Database, string? Plugin);

    private static Login ParseLogin(byte[] payload)
    {
        if (payload.Length < 34) throw new InvalidDataException();
        var capabilities = BinaryPrimitives.ReadUInt32LittleEndian(payload);
        if ((capabilities & Protocol41) == 0) throw new InvalidDataException();
        var offset = 32;
        var user = ReadString(payload, ref offset, 1024);
        int authLength;
        if ((capabilities & LengthEncodedAuth) != 0) authLength = ReadLength(payload, ref offset);
        else if ((capabilities & SecureConnection) != 0)
        {
            if (offset >= payload.Length) throw new InvalidDataException();
            authLength = payload[offset++];
        }
        else
        {
            var end = Array.IndexOf(payload, (byte)0, offset);
            if (end < 0) throw new InvalidDataException();
            authLength = end - offset;
        }
        if (authLength > payload.Length - offset) throw new InvalidDataException();
        var auth = payload.AsSpan(offset, authLength).ToArray(); offset += authLength;
        if ((capabilities & (LengthEncodedAuth | SecureConnection)) == 0) offset++;
        var database = (capabilities & ConnectWithDatabase) != 0 ? ReadString(payload, ref offset, 1024) : null;
        var plugin = (capabilities & PluginAuth) != 0 ? ReadString(payload, ref offset, 128) : null;
        if ((capabilities & ConnectAttributes) != 0 && offset < payload.Length)
        {
            var attributesLength = ReadLength(payload, ref offset);
            if (attributesLength > payload.Length - offset) throw new InvalidDataException();
            var end = offset + attributesLength;
            while (offset < end)
            {
                // 不保存可含敏感数据的连接属性，但严格检查 key/value 的边界。
                for (var i = 0; i < 2; i++)
                {
                    var length = ReadLength(payload, ref offset);
                    if (length > end - offset) throw new InvalidDataException();
                    offset += length;
                }
            }
        }
        if (offset != payload.Length) throw new InvalidDataException();
        return new Login(capabilities, user, auth, database, plugin);
    }

    private static string ReadPassword(byte[] bytes)
    {
        if (bytes.Length == 0 || bytes[^1] != 0 || bytes.AsSpan(0, bytes.Length - 1).Contains((byte)0))
            throw new InvalidDataException();
        return Utf8.GetString(bytes.AsSpan(0, bytes.Length - 1));
    }

    private static string ReadString(byte[] bytes, ref int offset, int maximum)
    {
        if (offset >= bytes.Length) throw new InvalidDataException();
        var end = Array.IndexOf(bytes, (byte)0, offset);
        if (end < 0 || end - offset > maximum) throw new InvalidDataException();
        var value = Utf8.GetString(bytes.AsSpan(offset, end - offset)); offset = end + 1;
        return value;
    }

    private static int ReadLength(byte[] bytes, ref int offset)
    {
        if (offset >= bytes.Length) throw new InvalidDataException();
        var first = bytes[offset++];
        if (first < 0xfb) return first;
        var size = first switch { 0xfc => 2, 0xfd => 3, 0xfe => 8, _ => throw new InvalidDataException() };
        if (size > bytes.Length - offset) throw new InvalidDataException();
        ulong length = 0;
        for (var i = 0; i < size; i++) length |= (ulong)bytes[offset++] << (i * 8);
        if (length > int.MaxValue) throw new InvalidDataException();
        return (int)length;
    }

    private static byte[] BuildError(bool hasPassword) => Join([0xff, 0x15, 0x04],
        Encoding.ASCII.GetBytes($"#28000Access denied for user (using password: {(hasPassword ? "YES" : "NO")})"));

    private static byte[] Join(params byte[][] values)
    {
        var output = new byte[values.Sum(x => x.Length)]; var offset = 0;
        foreach (var value in values) { value.CopyTo(output, offset); offset += value.Length; }
        return output;
    }

    /// <summary>包序号贯穿 SSLRequest 和 TLS 升级；每次读写同时受单帧及整个认证预算约束。</summary>
    private sealed class PacketConnection(IHoneypotSession session, ServiceProfile profile)
    {
        private byte _sequence;
        private long _bytes;
        public Stream? Stream { get; set; }
        public async ValueTask<byte[]> ReadAsync(CancellationToken ct)
        {
            var header = new byte[4]; await ReadExactAsync(header, ct);
            var length = header[0] | (header[1] << 8) | (header[2] << 16);
            if (header[3] != _sequence++ || length > Math.Min(profile.MaxFrameBytes, 65536) - 4) throw new InvalidDataException();
            Count(length + 4);
            var payload = new byte[length]; await ReadExactAsync(payload, ct); return payload;
        }
        public async ValueTask WriteAsync(byte[] payload, CancellationToken ct)
        {
            Count(payload.Length + 4);
            var packet = new byte[payload.Length + 4];
            packet[0] = (byte)payload.Length; packet[1] = (byte)(payload.Length >> 8); packet[2] = (byte)(payload.Length >> 16);
            packet[3] = _sequence++; payload.CopyTo(packet, 4);
            if (Stream is null) await session.WriteAsync(packet, ct); else await Stream.WriteAsync(packet, ct);
        }
        private async ValueTask ReadExactAsync(Memory<byte> buffer, CancellationToken ct)
        {
            var offset = 0;
            while (offset < buffer.Length)
            {
                var count = Stream is null ? await session.ReadAsync(buffer[offset..], ct) : await Stream.ReadAsync(buffer[offset..], ct);
                if (count == 0) throw new EndOfStreamException(); offset += count;
            }
        }
        private void Count(int count) { _bytes += count; if (_bytes > profile.MaxSessionBytes) throw new InvalidDataException(); }
    }
}
