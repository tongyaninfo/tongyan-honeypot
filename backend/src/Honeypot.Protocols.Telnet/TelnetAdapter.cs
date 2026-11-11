using System.Text;
using System.Text.Json;
using Honeypot.Protocol.Abstractions.Models;
using Honeypot.Protocol.Abstractions.Service;
using Honeypot.Protocols.Common;

namespace Honeypot.Protocols.Telnet;

/// <summary>受控 Linux 登录提示与 Telnet IAC 协商；密码不回显，永不创建 shell。</summary>
public sealed class TelnetAdapter : ProtocolAdapterBase
{
    public override ServiceAdapterDescriptor Descriptor => new()
    {
        AdapterKey = "telnet", DisplayName = "Telnet", SupportedFidelityLevels = ["L1", "L2", "L3"],
        SupportedClients = ["Telnet (Homebrew 308)"],
    };

    public override async ValueTask HandleAsync(IHoneypotSession session, ProtocolSessionContext context,
        ServiceProfile profile, IInteractionEventSink sink, CancellationToken cancellationToken = default)
    {
        var close = SessionCloseReason.AdapterCompleted;
        try
        {
            // WILL ECHO 让客户端停止本地回显；用户名由服务端回显，密码阶段不发送输入字节。
            await session.WriteAsync(new byte[] { 255, 251, 1, 255, 251, 3, 255, 253, 3 }, cancellationToken);
            var terminal = new Terminal(session, profile.MaxFrameBytes);
            var host = ProtocolFingerprint.HostName(profile);
            var attempts = 0;
            for (var prompts = 0; prompts < 128 && attempts < profile.MaxAuthenticationAttempts; prompts++)
            {
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                timeout.CancelAfter(prompts == 0 ? profile.HandshakeTimeout : profile.IdleTimeout);
                var ct = timeout.Token;
                await terminal.WriteAsync($"{host} login: ", ct);
                var user = await terminal.LineAsync(true, ct);
                if (user is null) break;
                if (user.Length == 0) continue;
                await terminal.WriteAsync("Password: ", ct);
                var password = await terminal.LineAsync(false, ct);
                if (password is null) break;
                await RecordAuthenticationAsync(sink, context, profile, user, "password", "LOGIN_INCORRECT", ++attempts,
                    "Plaintext", JsonSerializer.SerializeToUtf8Bytes(new { protocol = "telnet", username = user, password }), ct);
                await terminal.WriteAsync("Login incorrect\r\n\r\n", ct);
            }
        }
        catch (AuthenticationRecordingException) { close = SessionCloseReason.StorageDegraded; }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) { close = SessionCloseReason.IdleTimeout; }
        catch (Exception ex) when (ex is InvalidDataException or DecoderFallbackException)
        {
            close = SessionCloseReason.ProtocolViolation;
            await sink.AppendAsync(Event(context, "ProtocolViolation", "telnet", "rejected", "Invalid Telnet negotiation or input"), cancellationToken);
        }
        catch (IOException) { close = SessionCloseReason.ClientClosed; }
        catch (OperationCanceledException) { close = SessionCloseReason.ListenerStopping; throw; }
        catch (Exception) { close = SessionCloseReason.InternalError; throw; }
        finally { await session.CloseAsync(close, CancellationToken.None); }
    }

    private sealed class Terminal(IHoneypotSession session, int maximum)
    {
        private readonly byte[] _one = new byte[1];
        private bool _skipCrTail;
        private bool _echo = true;
        private readonly HashSet<byte> _rejectedLocal = [];
        private readonly HashSet<byte> _rejectedRemote = [];
        private int _negotiationBytes;
        public ValueTask WriteAsync(string value, CancellationToken ct) => session.WriteAsync(Encoding.UTF8.GetBytes(value), ct);
        private async ValueTask<int> ByteAsync(CancellationToken ct)
        {
            var count = await session.ReadAsync(_one, ct);
            return count == 0 ? -1 : _one[0];
        }
        private async ValueTask<int> DataAsync(CancellationToken ct)
        {
            while (true)
            {
                var value = await ByteAsync(ct);
                if (value != 255) return value;
                if (++_negotiationBytes > maximum) throw new InvalidDataException();
                var command = await ByteAsync(ct);
                if (command < 0) throw new EndOfStreamException();
                if (command == 255) return 255;
                if (command is 251 or 252 or 253 or 254)
                {
                    var option = await ByteAsync(ct);
                    if (option < 0) throw new EndOfStreamException();
                    if (command == 253 && option == 1) _echo = true;
                    else if (command == 254 && option == 1) _echo = false;
                    else if (command == 253 && option != 3 && _rejectedLocal.Add((byte)option))
                        await session.WriteAsync(new byte[] { 255, 252, (byte)option }, ct);
                    else if (command == 251 && option != 3 && _rejectedRemote.Add((byte)option))
                        await session.WriteAsync(new byte[] { 255, 254, (byte)option }, ct);
                }
                else if (command == 250)
                {
                    // 不需要终端子协商内容；仍逐字节有界消费，正确识别转义 IAC。
                    while (true)
                    {
                        if (++_negotiationBytes > maximum) throw new InvalidDataException();
                        var sub = await ByteAsync(ct);
                        if (sub < 0) throw new EndOfStreamException();
                        if (sub != 255) continue;
                        var end = await ByteAsync(ct);
                        if (end == 240) break;
                        if (end != 255) throw new InvalidDataException();
                    }
                }
                else if (command is 244 or 236) return -1; // Interrupt Process / EOF。
                else if (command == 247) return 8; // Erase Character。
                else if (command == 248) return 21; // Erase Line。
                else if (command is not (241 or 242 or 243 or 245 or 246 or 249)) throw new InvalidDataException();
            }
        }
        public async ValueTask<string?> LineAsync(bool echo, CancellationToken ct)
        {
            var line = new List<byte>();
            var received = 0;
            while (true)
            {
                var value = await DataAsync(ct);
                if (value < 0) return null;
                if (++received > maximum) throw new InvalidDataException();
                if (_skipCrTail)
                {
                    _skipCrTail = false;
                    if (value is 0 or 10) continue;
                }
                if (value is 13 or 10)
                {
                    _skipCrTail = value == 13;
                    await WriteAsync("\r\n", ct);
                    return new UTF8Encoding(false, true).GetString(line.ToArray());
                }
                if (value is 8 or 127)
                {
                    if (line.Count > 0)
                    {
                        // 退格按一个 UTF-8 字符删除，避免将中文用户名截成无效字节串。
                        var start = line.Count - 1;
                        while (start > 0 && (line[start] & 0xc0) == 0x80) start--;
                        line.RemoveRange(start, line.Count - start);
                        if (echo && _echo) await WriteAsync("\b \b", ct);
                    }
                    continue;
                }
                if (value == 21)
                {
                    if (echo && _echo) await WriteAsync(string.Concat(Enumerable.Repeat("\b \b", line.Count)), ct);
                    line.Clear(); continue;
                }
                if (value is 0 or 3 or 4) return null;
                if (value < 32) continue;
                line.Add((byte)value);
                if (echo && _echo) await session.WriteAsync(new byte[] { (byte)value }, ct);
            }
        }
    }
}
