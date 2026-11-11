using System.Buffers.Binary;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Honeypot.Protocol.Abstractions.Models;
using Honeypot.Protocol.Abstractions.Service;
using Honeypot.Protocols.Common;

namespace Honeypot.Protocols.PostgreSql;

/// <summary>PostgreSQL 启动和认证交换；无论材料是什么均返回 28P01，从不进入 SQL 阶段。</summary>
public sealed class PostgreSqlAdapter : ProtocolAdapterBase
{
    private static readonly UTF8Encoding Utf8 = new(false, true);
    public override ServiceAdapterDescriptor Descriptor => new()
    {
        AdapterKey = "postgresql", DisplayName = "PostgreSQL", SupportedFidelityLevels = ["L1", "L2", "L3"],
        SupportedClients = ["psql", "Npgsql"],
    };

    public override async ValueTask<AdapterValidationResult> ValidateAsync(ServiceProfile profile, CancellationToken cancellationToken = default)
    {
        var result = await base.ValidateAsync(profile, cancellationToken);
        return !result.IsValid || profile.PostgreSqlAuthenticationMethod is "scram-sha-256" or "password" or "md5"
            ? result : AdapterValidationResult.Invalid("POSTGRESQL_AUTH_UNSUPPORTED", "unsupported PostgreSQL authentication method");
    }

    public override async ValueTask HandleAsync(IHoneypotSession session, ProtocolSessionContext context,
        ServiceProfile profile, IInteractionEventSink sink, CancellationToken cancellationToken = default)
    {
        var close = SessionCloseReason.AdapterCompleted;
        SslStream? tls = null;
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(profile.HandshakeTimeout);
        var ct = timeout.Token;
        try
        {
            var wire = new Wire(session, profile.MaxFrameBytes);
            byte[] startup;
            var sawSsl = false; var sawGss = false;
            while (true)
            {
                startup = await wire.StartupAsync(ct);
                var request = BinaryPrimitives.ReadInt32BigEndian(startup);
                if (request == 80877103 && startup.Length == 4 && !sawSsl)
                {
                    sawSsl = true;
                    if (session is not IRawStreamHoneypotSession raw)
                    { await wire.WriteAsync("N"u8.ToArray(), ct); continue; }
                    await wire.WriteAsync("S"u8.ToArray(), ct);
                    using var certificate = ProtocolTls.CreateServerCertificate(ProtocolFingerprint.HostName(profile));
                    tls = new SslStream(raw.RawStream, true);
                    await tls.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
                    {
                        ServerCertificate = certificate, EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                        ClientCertificateRequired = false,
                    }, ct);
                    wire.Stream = tls;
                    continue;
                }
                if (request == 80877104 && startup.Length == 4 && !sawGss && !sawSsl)
                { sawGss = true; await wire.WriteAsync("N"u8.ToArray(), ct); continue; }
                if (request == 80877102 && startup.Length == 12) return; // CancelRequest 不包含认证材料。
                break;
            }
            var protocol = BinaryPrimitives.ReadUInt32BigEndian(startup);
            if ((protocol >> 16) != 3) throw new InvalidDataException();
            if ((protocol & 65535) != 0)
                await wire.MessageAsync((byte)'v', new byte[8], ct); // 仅支持协议 3.0，明确协商 minor 版本。
            var parameters = ParseStartup(startup.AsSpan(4));
            if (!parameters.TryGetValue("user", out var username) || username.Length == 0) throw new InvalidDataException();
            parameters.TryGetValue("database", out var database);
            database ??= username;
            await sink.AppendAsync(Event(context, "HandshakeReceived", "startup", "observed", "PostgreSQL protocol 3 startup"), ct);

            var method = profile.PostgreSqlAuthenticationMethod;
            byte[] material;
            var type = "Response";
            if (method == "scram-sha-256")
            {
                await wire.AuthenticationAsync(10, "SCRAM-SHA-256\0\0"u8.ToArray(), ct);
                var initial = await wire.PasswordAsync(ct);
                var separator = Array.IndexOf(initial, (byte)0);
                if (separator < 0 || separator + 5 > initial.Length || Utf8.GetString(initial, 0, separator) != "SCRAM-SHA-256")
                    throw new InvalidDataException();
                var initialLength = BinaryPrimitives.ReadInt32BigEndian(initial.AsSpan(separator + 1));
                if (initialLength < 0 || initialLength != initial.Length - separator - 5) throw new InvalidDataException();
                var first = Utf8.GetString(initial, separator + 5, initialLength);
                var firstComma = first.IndexOf(',');
                var secondComma = firstComma < 0 ? -1 : first.IndexOf(',', firstComma + 1);
                if (firstComma != 1 || secondComma < 2 || first[0] is not ('n' or 'y')) throw new InvalidDataException();
                var authorization = first[(firstComma + 1)..secondComma];
                if (authorization.Length != 0 && !authorization.StartsWith("a=", StringComparison.Ordinal)) throw new InvalidDataException();
                var gs2 = first[..(secondComma + 1)];
                var firstBare = first[(secondComma + 1)..];
                var attributes = Attributes(firstBare);
                if (attributes.ContainsKey('m') || !attributes.ContainsKey('n') || !attributes.TryGetValue('r', out var clientNonce) ||
                    clientNonce.Length is < 1 or > 1024 || clientNonce.Any(c => c < 33 || c > 126 || c == ',')) throw new InvalidDataException();
                var nonce = clientNonce + Convert.ToBase64String(RandomNumberGenerator.GetBytes(24));
                var salt = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));
                var serverFirst = $"r={nonce},s={salt},i=4096";
                await wire.AuthenticationAsync(11, Utf8.GetBytes(serverFirst), ct);
                var final = Utf8.GetString(await wire.PasswordAsync(ct));
                var finalAttributes = Attributes(final);
                if (!finalAttributes.TryGetValue('r', out var suppliedNonce) || suppliedNonce != nonce ||
                    !finalAttributes.TryGetValue('c', out var binding) || !finalAttributes.TryGetValue('p', out var proof) ||
                    finalAttributes.ContainsKey('m') || !final.EndsWith(",p=" + proof, StringComparison.Ordinal) ||
                    Convert.FromBase64String(proof).Length != 32 ||
                    !Convert.FromBase64String(binding).AsSpan().SequenceEqual(Utf8.GetBytes(gs2))) throw new InvalidDataException();
                // 挑战和客户端 proof 足够取证；没有密码或可验证的真实账号，不能冒充密码原文。
                material = JsonSerializer.SerializeToUtf8Bytes(new
                { protocol = "postgresql", username, database, password = (string?)null, mechanism = "SCRAM-SHA-256", clientFirst = first, serverFirst, clientFinal = final, tls = tls is not null });
            }
            else if (method is "password" or "md5")
            {
                var salt = method == "md5" ? RandomNumberGenerator.GetBytes(4) : [];
                await wire.AuthenticationAsync(method == "md5" ? 5 : 3, salt, ct);
                var response = await wire.PasswordAsync(ct);
                if (response.Length < 1 || response[^1] != 0 || response.AsSpan(0, response.Length - 1).Contains((byte)0))
                    throw new InvalidDataException();
                var value = Utf8.GetString(response, 0, response.Length - 1);
                if (method == "md5" && (value.Length != 35 || !value.StartsWith("md5", StringComparison.Ordinal) ||
                    value.AsSpan(3).ContainsAnyExcept("0123456789abcdef"))) throw new InvalidDataException();
                type = method == "password" ? "Plaintext" : "Response";
                material = JsonSerializer.SerializeToUtf8Bytes(new
                {
                    protocol = "postgresql", username, database, password = method == "password" ? value : null,
                    response = method == "md5" ? value : null, salt = Convert.ToBase64String(salt), tls = tls is not null,
                });
            }
            else throw new InvalidDataException();
            await RecordAuthenticationAsync(sink, context, profile, username, method, "28P01", 1, type, material, ct, database: database);
            await wire.MessageAsync((byte)'E', Utf8.GetBytes($"SFATAL\0VFATAL\0C28P01\0Mpassword authentication failed for user \"{username}\"\0\0"), ct);
        }
        catch (AuthenticationRecordingException) { close = SessionCloseReason.StorageDegraded; }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) { close = SessionCloseReason.HandshakeTimeout; }
        catch (Exception ex) when (ex is InvalidDataException or DecoderFallbackException or FormatException)
        {
            close = SessionCloseReason.ProtocolViolation;
            await sink.AppendAsync(Event(context, "ProtocolViolation", "authentication", "rejected", "Invalid PostgreSQL authentication exchange"), cancellationToken);
        }
        catch (AuthenticationException)
        {
            close = SessionCloseReason.ProtocolViolation;
            await sink.AppendAsync(Event(context, "ProtocolViolation", "tls", "rejected", "PostgreSQL TLS negotiation failed"), cancellationToken);
        }
        catch (IOException) { close = SessionCloseReason.ClientClosed; }
        catch (OperationCanceledException) { close = SessionCloseReason.ListenerStopping; throw; }
        catch (Exception) { close = SessionCloseReason.InternalError; throw; }
        finally
        {
            if (tls is not null) await tls.DisposeAsync();
            await session.CloseAsync(close, CancellationToken.None);
        }
    }

    private static Dictionary<string, string> ParseStartup(ReadOnlySpan<byte> payload)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        while (payload.Length > 1)
        {
            var end = payload.IndexOf((byte)0);
            if (end <= 0) throw new InvalidDataException();
            var key = Utf8.GetString(payload[..end]); payload = payload[(end + 1)..];
            end = payload.IndexOf((byte)0);
            if (end < 0 || result.Count >= 64) throw new InvalidDataException();
            var value = Utf8.GetString(payload[..end]); payload = payload[(end + 1)..];
            if (!result.TryAdd(key, value)) throw new InvalidDataException();
        }
        if (payload.Length != 1 || payload[0] != 0) throw new InvalidDataException();
        return result;
    }
    private static Dictionary<char, string> Attributes(string value)
    {
        var result = new Dictionary<char, string>();
        foreach (var field in value.Split(','))
            if (field.Length < 2 || field[1] != '=' || !result.TryAdd(field[0], field[2..])) throw new InvalidDataException();
        return result;
    }

    private sealed class Wire(IHoneypotSession session, int maximum)
    {
        public Stream? Stream { get; set; }
        private async ValueTask ExactAsync(Memory<byte> memory, CancellationToken ct)
        {
            for (var offset = 0; offset < memory.Length;)
            {
                var count = Stream is null ? await session.ReadAsync(memory[offset..], ct) : await Stream.ReadAsync(memory[offset..], ct);
                if (count == 0) throw new EndOfStreamException();
                offset += count;
            }
        }
        public ValueTask WriteAsync(ReadOnlyMemory<byte> value, CancellationToken ct) =>
            Stream is null ? session.WriteAsync(value, ct) : Stream.WriteAsync(value, ct);
        public async ValueTask<byte[]> StartupAsync(CancellationToken ct)
        {
            var lengthBytes = new byte[4]; await ExactAsync(lengthBytes, ct);
            var length = BinaryPrimitives.ReadInt32BigEndian(lengthBytes);
            if (length < 8 || length > maximum) throw new InvalidDataException();
            var payload = new byte[length - 4]; await ExactAsync(payload, ct); return payload;
        }
        public async ValueTask<byte[]> PasswordAsync(CancellationToken ct)
        {
            var header = new byte[5]; await ExactAsync(header, ct);
            var length = BinaryPrimitives.ReadInt32BigEndian(header.AsSpan(1));
            if (header[0] != 'p' || length < 4 || length > maximum - 1) throw new InvalidDataException();
            var payload = new byte[length - 4]; await ExactAsync(payload, ct); return payload;
        }
        public ValueTask MessageAsync(byte type, byte[] payload, CancellationToken ct)
        {
            var bytes = new byte[payload.Length + 5]; bytes[0] = type;
            BinaryPrimitives.WriteInt32BigEndian(bytes.AsSpan(1), payload.Length + 4); payload.CopyTo(bytes, 5);
            return WriteAsync(bytes, ct);
        }
        public ValueTask AuthenticationAsync(int type, byte[] payload, CancellationToken ct)
        {
            var bytes = new byte[payload.Length + 4]; BinaryPrimitives.WriteInt32BigEndian(bytes, type); payload.CopyTo(bytes, 4);
            return MessageAsync((byte)'R', bytes, ct);
        }
    }
}
