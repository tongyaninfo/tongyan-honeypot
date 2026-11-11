using System.Globalization;
using System.Text;
using System.Text.Json;
using Honeypot.Protocol.Abstractions.Models;
using Honeypot.Protocol.Abstractions.Service;
using Honeypot.Protocols.Common;

namespace Honeypot.Protocols.Redis;

/// <summary>RESP2/3 认证蜜罐：密码提交始终 WRONGPASS，不建立可执行命令的会话。</summary>
public sealed class RedisAdapter : ProtocolAdapterBase
{
    public override ServiceAdapterDescriptor Descriptor => new()
    {
        AdapterKey = "redis", DisplayName = "Redis", SupportedFidelityLevels = ["L1", "L2", "L3"],
        SupportedClients = ["redis-cli", "StackExchange.Redis"],
    };

    public override async ValueTask HandleAsync(IHoneypotSession session, ProtocolSessionContext context,
        ServiceProfile profile, IInteractionEventSink sink, CancellationToken cancellationToken = default)
    {
        var close = SessionCloseReason.AdapterCompleted;
        var attempts = 0;
        try
        {
            for (var requests = 0; requests < 128 && attempts < profile.MaxAuthenticationAttempts; requests++)
            {
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                timeout.CancelAfter(requests == 0 ? profile.HandshakeTimeout : profile.IdleTimeout);
                var ct = timeout.Token;
                var reader = new RespReader(session, profile.MaxFrameBytes);
                var args = await reader.CommandAsync(ct);
                if (args is null) break;
                if (args.Count == 0) continue;
                var command = Encoding.UTF8.GetString(args[0]).ToUpperInvariant();
                byte[]? user = null, password = null;
                if (command == "AUTH")
                {
                    if (args.Count == 2) { user = "default"u8.ToArray(); password = args[1]; }
                    else if (args.Count == 3) { user = args[1]; password = args[2]; }
                    else { await WriteAsync(session, "-ERR wrong number of arguments for 'auth' command\r\n", ct); continue; }
                }
                else if (command == "HELLO")
                {
                    if (args.Count < 2 || !int.TryParse(Encoding.ASCII.GetString(args[1]), out var version) || version is not (2 or 3))
                    { await WriteAsync(session, "-NOPROTO unsupported protocol version\r\n", ct); continue; }
                    var valid = true;
                    for (var i = 2; i < args.Count;)
                    {
                        var option = Encoding.ASCII.GetString(args[i]).ToUpperInvariant();
                        if (option == "AUTH" && i + 2 < args.Count)
                        { user = args[i + 1]; password = args[i + 2]; i += 3; }
                        else if (option == "SETNAME" && i + 1 < args.Count) i += 2;
                        else { valid = false; break; }
                    }
                    if (!valid) { await WriteAsync(session, "-ERR Syntax error in HELLO option\r\n", ct); continue; }
                    if (password is null)
                    { await WriteAsync(session, "-NOAUTH HELLO must be called with the client already authenticated, otherwise the HELLO AUTH <user> <pass> option can be used to authenticate the client and select the RESP protocol version at the same time\r\n", ct); continue; }
                }
                else if (command == "QUIT")
                { await WriteAsync(session, "+OK\r\n", ct); break; }
                else if (command == "RESET")
                { await WriteAsync(session, "+RESET\r\n", ct); continue; }
                else
                { await WriteAsync(session, "-NOAUTH Authentication required.\r\n", ct); continue; }

                var username = Decode(user!);
                var plaintext = Decode(password!);
                var material = JsonSerializer.SerializeToUtf8Bytes(new
                {
                    protocol = "redis", username, password = plaintext,
                    usernameBase64 = Convert.ToBase64String(user!), passwordBase64 = Convert.ToBase64String(password!),
                    command, encoding = plaintext is null ? "binary" : "utf8",
                });
                await RecordAuthenticationAsync(sink, context, profile, username, command == "HELLO" ? "HELLO AUTH" : "AUTH",
                    "WRONGPASS", ++attempts, "Plaintext", material, ct);
                await WriteAsync(session, "-WRONGPASS invalid username-password pair or user is disabled.\r\n", ct);
            }
        }
        catch (AuthenticationRecordingException) { close = SessionCloseReason.StorageDegraded; }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) { close = SessionCloseReason.IdleTimeout; }
        catch (InvalidDataException)
        {
            close = SessionCloseReason.ProtocolViolation;
            await sink.AppendAsync(Event(context, "ProtocolViolation", "resp", "rejected", "Invalid RESP request"), cancellationToken);
        }
        catch (EndOfStreamException) { close = SessionCloseReason.ClientClosed; }
        catch (IOException) { close = SessionCloseReason.ClientClosed; }
        catch (OperationCanceledException) { close = SessionCloseReason.ListenerStopping; throw; }
        catch (Exception) { close = SessionCloseReason.InternalError; throw; }
        finally { await session.CloseAsync(close, CancellationToken.None); }
    }

    private static string? Decode(byte[] value)
    {
        try { return new UTF8Encoding(false, true).GetString(value); }
        catch (DecoderFallbackException) { return null; }
    }
    private static ValueTask WriteAsync(IHoneypotSession session, string value, CancellationToken ct) =>
        session.WriteAsync(Encoding.UTF8.GetBytes(value), ct);

    /// <summary>逐请求限制总帧长，bulk 长度先验证后分配；不递归解析任意 RESP 树。</summary>
    private sealed class RespReader(IHoneypotSession session, int maximum)
    {
        private int _read;
        private readonly byte[] _single = new byte[1];
        private async ValueTask<int> ByteAsync(CancellationToken ct)
        {
            if (_read >= maximum) throw new InvalidDataException();
            var count = await session.ReadAsync(_single, ct);
            if (count == 0) return -1;
            _read++; return _single[0];
        }
        private async ValueTask<byte[]> LineAsync(int first, CancellationToken ct)
        {
            using var line = new MemoryStream();
            var current = first;
            while (current != 13)
            {
                if (current < 0 || current == 10) throw new InvalidDataException();
                line.WriteByte((byte)current); current = await ByteAsync(ct);
            }
            if (await ByteAsync(ct) != 10) throw new InvalidDataException();
            return line.ToArray();
        }
        public async ValueTask<List<byte[]>?> CommandAsync(CancellationToken ct)
        {
            var first = await ByteAsync(ct);
            if (first < 0) return null;
            if (first != '*') return ParseInline(await LineAsync(first, ct));
            var number = Encoding.ASCII.GetString(await LineAsync(await ByteAsync(ct), ct));
            if (!int.TryParse(number, NumberStyles.None, CultureInfo.InvariantCulture, out var count) || count is < 1 or > 128)
                throw new InvalidDataException();
            var args = new List<byte[]>(count);
            for (var i = 0; i < count; i++)
            {
                if (await ByteAsync(ct) != '$') throw new InvalidDataException();
                number = Encoding.ASCII.GetString(await LineAsync(await ByteAsync(ct), ct));
                if (!int.TryParse(number, NumberStyles.None, CultureInfo.InvariantCulture, out var length) || length > maximum - _read - 2)
                    throw new InvalidDataException();
                var value = new byte[length];
                for (var offset = 0; offset < length;)
                {
                    var read = await session.ReadAsync(value.AsMemory(offset), ct);
                    if (read == 0) throw new EndOfStreamException();
                    offset += read; _read += read;
                }
                if (await ByteAsync(ct) != 13 || await ByteAsync(ct) != 10) throw new InvalidDataException();
                args.Add(value);
            }
            return args;
        }
        private static List<byte[]> ParseInline(byte[] line)
        {
            var args = new List<byte[]>();
            for (var i = 0; i < line.Length;)
            {
                while (i < line.Length && line[i] is 32 or 9) i++;
                if (i == line.Length) break;
                using var value = new MemoryStream();
                var quote = 0;
                while (i < line.Length)
                {
                    var c = line[i++];
                    if (quote == 0 && c is 32 or 9) break;
                    if (quote == 0 && c is 34 or 39) { quote = c; continue; }
                    if (quote == c)
                    {
                        quote = 0;
                        if (i < line.Length && line[i] is not (32 or 9)) throw new InvalidDataException();
                        break;
                    }
                    // Redis 单引号内只转义单引号；其余反斜杠必须作为密码原文保留。
                    if (c == 92 && i < line.Length && (quote == 34 || quote == 39 && line[i] == 39))
                    {
                        c = line[i++];
                        if (quote == 34 && c == 'x' && i + 1 < line.Length &&
                            byte.TryParse(Encoding.ASCII.GetString(line, i, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var hex))
                        { c = hex; i += 2; }
                        else if (quote == 34) c = c switch { (byte)'n' => 10, (byte)'r' => 13, (byte)'t' => 9, (byte)'b' => 8, (byte)'a' => 7, _ => c };
                    }
                    value.WriteByte(c);
                }
                if (quote != 0 || args.Count >= 128) throw new InvalidDataException();
                args.Add(value.ToArray());
            }
            return args;
        }
    }
}
