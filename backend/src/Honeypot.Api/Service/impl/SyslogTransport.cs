using System.Globalization;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Honeypot.Shared.Models;

namespace Honeypot.Api.Service.impl;

/// <summary>单目标 UDP/TCP/TLS/RELP；错误内容固定，避免接收端响应进入普通日志。</summary>
public sealed class SyslogTransport : ISyslogTransport
{
    private readonly SyslogTarget _target;
    private readonly TimeSpan _timeout;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly byte[] _singleByte = new byte[1];
    private TcpClient? _client;
    private Socket? _datagram;
    private Stream? _stream;
    private int _transaction = 1;
    private bool _relpOpened;
    private bool _disposed;

    public SyslogTransport(SyslogTarget target, TimeSpan? timeout = null)
    {
        ArgumentNullException.ThrowIfNull(target);
        if (string.IsNullOrWhiteSpace(target.Host) || target.Port is < 1 or > 65535 || !Enum.IsDefined(target.Protocol))
            throw new ArgumentException("SYSLOG_TARGET_INVALID", nameof(target));
        _target = target;
        _timeout = timeout ?? TimeSpan.FromSeconds(10);
        if (_timeout <= TimeSpan.Zero || _timeout > TimeSpan.FromMinutes(5)) throw new ArgumentOutOfRangeException(nameof(timeout));
    }

    public Task ConnectAsync(CancellationToken cancellationToken = default) => ExecuteAsync(async token =>
    {
        await ConnectCoreAsync(token);
        return true;
    }, cancellationToken);

    public Task<SyslogSendResult> SendAsync(ReadOnlyMemory<byte> message, CancellationToken cancellationToken = default)
    {
        var maximum = _target.Protocol == SyslogProtocol.Udp ? 1200 : 8192;
        if (message.Length == 0 || message.Length > maximum) throw new ArgumentException("SYSLOG_MESSAGE_SIZE_INVALID", nameof(message));
        return ExecuteAsync(async token =>
        {
            await ConnectCoreAsync(token);
            if (_target.Protocol == SyslogProtocol.Udp)
            {
                var sent = await _datagram!.SendAsync(message, SocketFlags.None, token);
                if (sent != message.Length) throw new IOException("SYSLOG_DATAGRAM_INCOMPLETE");
                return new SyslogSendResult(SyslogDeliveryStage.LocalSubmitted);
            }
            if (_target.Protocol == SyslogProtocol.Relp)
            {
                var transaction = NextTransaction();
                await WriteRelpAsync(transaction, "syslog", message, token);
                _ = await ReadRelpResponseAsync(transaction, token);
                return new SyslogSendResult(SyslogDeliveryStage.RelpAcknowledged);
            }
            // 长度仅包含 Syslog 消息的 UTF-8 字节，不包含前缀；换行不充当边界。
            var prefix = Encoding.ASCII.GetBytes(message.Length.ToString(CultureInfo.InvariantCulture) + " ");
            await _stream!.WriteAsync(prefix, token);
            await _stream.WriteAsync(message, token);
            await _stream.FlushAsync(token);
            return new SyslogSendResult(SyslogDeliveryStage.TransportWritten);
        }, cancellationToken);
    }

    private async Task<T> ExecuteAsync<T>(Func<CancellationToken, Task<T>> operation, CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            deadline.CancelAfter(_timeout);
            try { return await operation(deadline.Token); }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                ResetConnection();
                throw new TimeoutException("SYSLOG_OPERATION_TIMEOUT");
            }
            catch (OperationCanceledException) { ResetConnection(); throw; }
            catch (AuthenticationException) { ResetConnection(); throw new AuthenticationException("SYSLOG_TLS_VALIDATION_FAILED"); }
            catch (Exception error) when (error is IOException or SocketException)
            {
                ResetConnection();
                throw new IOException("SYSLOG_TRANSPORT_FAILED");
            }
        }
        finally { _gate.Release(); }
    }

    private async Task ConnectCoreAsync(CancellationToken cancellationToken)
    {
        if (_stream is not null || _datagram is not null) return;
        if (_target.Protocol == SyslogProtocol.Udp)
        {
            var addresses = await Dns.GetHostAddressesAsync(_target.Host, cancellationToken);
            var address = addresses.FirstOrDefault() ?? throw new IOException("SYSLOG_DNS_EMPTY");
            _datagram = new Socket(address.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
            await _datagram.ConnectAsync(new IPEndPoint(address, _target.Port), cancellationToken);
            return;
        }
        _client = new TcpClient { NoDelay = true };
        await _client.ConnectAsync(_target.Host, _target.Port, cancellationToken);
        _stream = _client.GetStream();
        if (_target.Protocol == SyslogProtocol.Tls)
        {
            // 回调只属于当前目标；允许忽略证书错误也绝不切换成明文或全局放宽。
            var tls = new SslStream(_stream, leaveInnerStreamOpen: false,
                (_, _, _, errors) => _target.IgnoreSslErrors || errors == SslPolicyErrors.None);
            _stream = tls;
            await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = _target.Host,
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                CertificateRevocationCheckMode = X509RevocationMode.Online
            }, cancellationToken);
        }
        if (_target.Protocol == SyslogProtocol.Relp)
        {
            _transaction = 1;
            // 当前 librelp 的 RELP_CURR_PROTOCOL_VERSION 为 0，与早期草案描述不同。
            var offer = Encoding.ASCII.GetBytes("relp_version=0\nrelp_software=honeypot,1\ncommands=syslog");
            var transaction = NextTransaction();
            await WriteRelpAsync(transaction, "open", offer, cancellationToken);
            var response = await ReadRelpResponseAsync(transaction, cancellationToken);
            var offers = response.Split('\n', StringSplitOptions.RemoveEmptyEntries).Skip(1).ToArray();
            if (!offers.Contains("relp_version=0", StringComparer.Ordinal)
                || !offers.Any(value => value.StartsWith("commands=", StringComparison.Ordinal) && value[9..].Split(',').Contains("syslog", StringComparer.Ordinal)))
                throw new IOException("SYSLOG_RELP_NEGOTIATION_FAILED");
            _relpOpened = true;
        }
    }

    private int NextTransaction()
    {
        var value = _transaction;
        _transaction = value == 999999999 ? 1 : value + 1;
        return value;
    }

    private async Task WriteRelpAsync(int transaction, string command, ReadOnlyMemory<byte> data, CancellationToken cancellationToken)
    {
        var prefix = Encoding.ASCII.GetBytes($"{transaction.ToString(CultureInfo.InvariantCulture)} {command} {data.Length.ToString(CultureInfo.InvariantCulture)}" + (data.Length > 0 ? " " : ""));
        await _stream!.WriteAsync(prefix, cancellationToken);
        if (data.Length > 0) await _stream.WriteAsync(data, cancellationToken);
        await _stream.WriteAsync(new byte[] { (byte)'\n' }, cancellationToken);
        await _stream.FlushAsync(cancellationToken);
    }

    private async Task<string> ReadRelpResponseAsync(int expectedTransaction, CancellationToken cancellationToken, bool allowEmpty = false)
    {
        var transaction = await ReadTokenAsync(9, cancellationToken);
        var command = await ReadTokenAsync(32, cancellationToken);
        var (lengthText, delimiter) = await ReadLengthAsync(cancellationToken);
        if (!int.TryParse(transaction, NumberStyles.None, CultureInfo.InvariantCulture, out var receivedTransaction)
            || receivedTransaction != expectedTransaction || command != "rsp"
            || !int.TryParse(lengthText, NumberStyles.None, CultureInfo.InvariantCulture, out var length) || length is < 0 or > 16384)
            throw new IOException("SYSLOG_RELP_RESPONSE_INVALID");
        // librelp 的 close 正常响应是“tx rsp 0\n”；普通消息仍必须有 200 应答。
        if (length == 0 && delimiter == '\n' && allowEmpty) return string.Empty;
        if (length < 3 || delimiter != ' ') throw new IOException("SYSLOG_RELP_RESPONSE_INVALID");
        var data = new byte[length];
        await _stream!.ReadExactlyAsync(data, cancellationToken);
        if (await ReadByteAsync(cancellationToken) != '\n') throw new IOException("SYSLOG_RELP_FRAME_INVALID");
        var response = Encoding.UTF8.GetString(data);
        if (response != "200" && !response.StartsWith("200 ", StringComparison.Ordinal) && !response.StartsWith("200\n", StringComparison.Ordinal))
            throw new IOException("SYSLOG_RELP_REJECTED");
        return response;
    }

    private async Task<(string Value, int Delimiter)> ReadLengthAsync(CancellationToken cancellationToken)
    {
        var value = new StringBuilder(9);
        while (true)
        {
            var character = await ReadByteAsync(cancellationToken);
            if (character is ' ' or '\n' && value.Length > 0) return (value.ToString(), character);
            if (character is < '0' or > '9' || value.Length >= 9) throw new IOException("SYSLOG_RELP_HEADER_INVALID");
            value.Append((char)character);
        }
    }

    private async Task<string> ReadTokenAsync(int limit, CancellationToken cancellationToken)
    {
        var value = new StringBuilder(limit);
        while (true)
        {
            var character = await ReadByteAsync(cancellationToken);
            if (character == ' ' && value.Length > 0) return value.ToString();
            if (character is < '!' or > '~' || value.Length >= limit) throw new IOException("SYSLOG_RELP_HEADER_INVALID");
            value.Append((char)character);
        }
    }

    private async Task<int> ReadByteAsync(CancellationToken cancellationToken)
    {
        if (await _stream!.ReadAsync(_singleByte, cancellationToken) != 1) throw new EndOfStreamException("SYSLOG_REMOTE_CLOSED");
        return _singleByte[0];
    }

    private void ResetConnection()
    {
        _stream?.Dispose();
        _client?.Dispose();
        _datagram?.Dispose();
        _stream = null;
        _client = null;
        _datagram = null;
        _relpOpened = false;
    }

    public async ValueTask DisposeAsync()
    {
        await _gate.WaitAsync();
        try
        {
            if (_disposed) return;
            _disposed = true;
            if (_relpOpened && _stream is not null)
            {
                // 退出最多等待一秒；失败不递归产生日志，也不改变此前确认结果。
                using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(1));
                try
                {
                    var transaction = NextTransaction();
                    await WriteRelpAsync(transaction, "close", ReadOnlyMemory<byte>.Empty, deadline.Token);
                    _ = await ReadRelpResponseAsync(transaction, deadline.Token, allowEmpty: true);
                }
                catch (Exception error) when (error is IOException or SocketException or OperationCanceledException) { }
            }
            ResetConnection();
        }
        finally { _gate.Release(); }
    }
}
