using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Honeypot.Api.Common;
using Honeypot.Api.Service;
using Honeypot.Api.Service.impl;
using Honeypot.Shared.Models;
using Xunit;

namespace Honeypot.Runtime.Tests;

/// <summary>全部网络测试只使用回环和即时生成的合成证书，不修改系统信任或连接外部服务。</summary>
public sealed class SyslogTransportTests
{
    [Fact]
    public void FormatterProducesAsciiHeaderAndNoBodyHostname()
    {
        var record = Record() with
        {
            Fields = new Dictionary<string, object?>
            {
                ["outcome"] = "中文\n\0\"injected",
                ["hostname"] = "forbidden-host",
                ["displayHost"] = "forbidden-display",
                ["password"] = "synthetic-secret",
                ["nested"] = new { token = "synthetic-secret" }
            }
        };
        var bytes = SyslogMessageFormatter.Format(record, hostname: "tongyan-honeypot-SERVER01");
        var text = Encoding.UTF8.GetString(bytes);
        Assert.StartsWith("<133>1 2026-11-11T01:02:03.123456Z tongyan-honeypot-SERVER01 honeypot-ssh ", text);
        var split = text.IndexOf(" - \uFEFF", StringComparison.Ordinal);
        Assert.True(split > 0);
        Assert.All(text[..split], value => Assert.InRange(value, (char)32, (char)126));
        using var document = JsonDocument.Parse(text[(split + 4)..]);
        Assert.Equal("中文\n\0\"injected", document.RootElement.GetProperty("outcome").GetString());
        Assert.True(document.RootElement.GetProperty("fieldsSuppressed").GetBoolean());
        Assert.DoesNotContain("forbidden-", text);
        Assert.DoesNotContain("synthetic-secret", text);
        Assert.False(document.RootElement.TryGetProperty("hostname", out _));
        Assert.False(document.RootElement.TryGetProperty("displayHost", out _));
        Assert.DoesNotContain('\n', text);
    }

    [Fact]
    public void HostNormalizationIsStableAsciiAndCollisionResistant()
    {
        var hostname = SyslogMessageFormatter.BuildHostname("服务器一");
        Assert.StartsWith("tongyan-honeypot-", hostname);
        Assert.All(hostname, value => Assert.InRange(value, '!', '~'));
        Assert.Equal(hostname, SyslogMessageFormatter.BuildHostname("服务器一"));
        Assert.NotEqual(hostname, SyslogMessageFormatter.BuildHostname("服务器二"));
        Assert.True(SyslogMessageFormatter.BuildHostname(new string('x', 400)).Length <= 255);
        Assert.Equal("tongyan-honeypot-SERVER01", SyslogMessageFormatter.BuildHostname("SERVER01"));
    }

    [Fact]
    public void FormatterTruncatesOptionalFieldsWithoutBreakingJsonOrUtf8()
    {
        var record = Record() with { Fields = new Dictionary<string, object?> { ["outcome"] = new string('中', 2000) } };
        var bytes = SyslogMessageFormatter.Format(record, maxBytes: 480, hostname: "tongyan-honeypot-test");
        Assert.True(bytes.Length <= 480);
        using var json = ParseBody(bytes);
        Assert.True(json.RootElement.GetProperty("truncated").GetBoolean());
        Assert.Equal("synthetic-log-1", json.RootElement.GetProperty("logId").GetString());
        Assert.Throws<ArgumentException>(() => SyslogMessageFormatter.Format(record with { AppName = "bad\nheader" }));
        Assert.Throws<ArgumentException>(() => SyslogMessageFormatter.Format(record, hostname: "中文主机"));
    }

    [Theory]
    [InlineData(SyslogSeverity.Emergency, 128)]
    [InlineData(SyslogSeverity.Alert, 129)]
    [InlineData(SyslogSeverity.Critical, 130)]
    [InlineData(SyslogSeverity.Error, 131)]
    [InlineData(SyslogSeverity.Warning, 132)]
    [InlineData(SyslogSeverity.Notice, 133)]
    [InlineData(SyslogSeverity.Informational, 134)]
    [InlineData(SyslogSeverity.Debug, 135)]
    public void FormatterPreservesAllEightSeverities(SyslogSeverity severity, int priority)
        => Assert.StartsWith($"<{priority}>1 ", Encoding.UTF8.GetString(SyslogMessageFormatter.Format(Record() with { Severity = severity })));

    [Fact]
    public async Task UdpSendsOneDatagramAndReportsOnlyLocalSubmission()
    {
        using var receiver = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var port = ((IPEndPoint)receiver.Client.LocalEndPoint!).Port;
        await using var transport = new SyslogTransport(Target(port, SyslogProtocol.Udp));
        var payload = SyslogMessageFormatter.Format(Record(), maxBytes: 1200);
        var result = await transport.SendAsync(payload);
        var datagram = await receiver.ReceiveAsync().WaitAsync(TimeSpan.FromSeconds(3));
        Assert.Equal(payload, datagram.Buffer);
        Assert.Equal(SyslogDeliveryStage.LocalSubmitted, result.Stage);
    }

    [Fact]
    public async Task TcpUsesByteCountFramingAndReusesConnection()
    {
        var received = new TaskCompletionSource<byte[][]>(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var server = new LoopbackServer(async (client, token) =>
        {
            var stream = client.GetStream();
            received.SetResult([await ReadSyslogFrameAsync(stream, token), await ReadSyslogFrameAsync(stream, token)]);
        });
        await using var transport = new SyslogTransport(Target(server.Port, SyslogProtocol.Tcp));
        var payload = SyslogMessageFormatter.Format(Record());
        await transport.ConnectAsync();
        var first = await transport.SendAsync(payload);
        var second = await transport.SendAsync(payload);
        var records = await received.Task.WaitAsync(TimeSpan.FromSeconds(3));
        Assert.All(records, record => Assert.Equal(payload, record));
        Assert.Equal(SyslogDeliveryStage.TransportWritten, first.Stage);
        Assert.Equal(SyslogDeliveryStage.TransportWritten, second.Stage);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task TlsRejectsUntrustedCertificateUnlessCurrentTargetOptsIn(bool ignoreSslErrors)
    {
        using var certificate = CreateCertificate();
        var received = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var server = new LoopbackServer(async (client, token) =>
        {
            await using var stream = new SslStream(client.GetStream(), leaveInnerStreamOpen: false);
            try
            {
                await stream.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
                {
                    ServerCertificate = certificate,
                    EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                    ClientCertificateRequired = false
                }, token);
                received.TrySetResult(await ReadSyslogFrameAsync(stream, token));
            }
            catch (Exception error) when (error is IOException or AuthenticationException or OperationCanceledException) { }
        });
        await using var transport = new SyslogTransport(Target(server.Port, SyslogProtocol.Tls) with { IgnoreSslErrors = ignoreSslErrors });
        var payload = SyslogMessageFormatter.Format(Record());
        if (ignoreSslErrors)
        {
            Assert.Equal(SyslogDeliveryStage.TransportWritten, (await transport.SendAsync(payload)).Stage);
            Assert.Equal(payload, await received.Task.WaitAsync(TimeSpan.FromSeconds(3)));
        }
        else
        {
            await Assert.ThrowsAsync<AuthenticationException>(() => transport.SendAsync(payload));
            Assert.False(received.Task.IsCompletedSuccessfully);
        }
    }

    [Fact]
    public async Task RelpNegotiatesAndWaitsForMatchingAcknowledgement()
    {
        var payload = SyslogMessageFormatter.Format(Record());
        var seen = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        var permitAck = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var server = new LoopbackServer(async (client, token) =>
        {
            var stream = client.GetStream();
            await AcceptRelpOpenAsync(stream, token);
            var (transaction, command, data) = await ReadRelpFrameAsync(stream, token);
            Assert.Equal("syslog", command);
            seen.SetResult(data);
            await permitAck.Task.WaitAsync(token);
            // 拆分响应头和内容，确保客户端不依赖一次 Read 的边界。
            await SendResponseAsync(stream, transaction, "200 OK", token, fragmented: true);
            var close = await ReadRelpFrameAsync(stream, token);
            Assert.Equal("close", close.Command);
            // 真实 librelp 使用无 DATA 的 close 应答，不能只测试带 200 的替身。
            await stream.WriteAsync(Encoding.ASCII.GetBytes($"{close.Transaction} rsp 0\n"), token);
        });
        await using var transport = new SyslogTransport(Target(server.Port, SyslogProtocol.Relp));
        var send = transport.SendAsync(payload);
        Assert.Equal(payload, await seen.Task.WaitAsync(TimeSpan.FromSeconds(3)));
        Assert.False(send.IsCompleted);
        permitAck.SetResult();
        Assert.Equal(SyslogDeliveryStage.RelpAcknowledged, (await send).Stage);
    }

    [Theory]
    [InlineData("negative")]
    [InlineData("wrong-transaction")]
    [InlineData("oversize")]
    [InlineData("empty")]
    public async Task RelpRejectsNegativeMismatchedAndUnboundedResponses(string mode)
    {
        await using var server = new LoopbackServer(async (client, token) =>
        {
            var stream = client.GetStream();
            await AcceptRelpOpenAsync(stream, token);
            var frame = await ReadRelpFrameAsync(stream, token);
            if (mode == "oversize") await stream.WriteAsync(Encoding.ASCII.GetBytes($"{frame.Transaction} rsp 999999999 "), token);
            else if (mode == "empty") await stream.WriteAsync(Encoding.ASCII.GetBytes($"{frame.Transaction} rsp 0\n"), token);
            else await SendResponseAsync(stream, mode == "wrong-transaction" ? frame.Transaction + 1 : frame.Transaction,
                mode == "negative" ? "500 synthetic-remote-secret" : "200 OK", token);
        });
        await using var transport = new SyslogTransport(Target(server.Port, SyslogProtocol.Relp));
        var error = await Assert.ThrowsAsync<IOException>(() => transport.SendAsync(SyslogMessageFormatter.Format(Record())));
        Assert.DoesNotContain("synthetic-remote-secret", error.ToString());
    }

    [Fact]
    public async Task RelpStalledNegotiationHasFiniteDeadline()
    {
        await using var server = new LoopbackServer(async (_, token) => await Task.Delay(Timeout.InfiniteTimeSpan, token));
        await using var transport = new SyslogTransport(Target(server.Port, SyslogProtocol.Relp), TimeSpan.FromMilliseconds(200));
        await Assert.ThrowsAsync<TimeoutException>(() => transport.ConnectAsync());
    }

    [Fact]
    public async Task RelpLostAckCanBeRetriedWithStableMessageOnNewConnection()
    {
        var payload = SyslogMessageFormatter.Format(Record());
        var firstSeen = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        var retrySeen = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var server = new LoopbackServer(async (client, token) =>
        {
            var stream = client.GetStream();
            await AcceptRelpOpenAsync(stream, token);
            var frame = await ReadRelpFrameAsync(stream, token);
            if (!firstSeen.Task.IsCompleted)
            {
                firstSeen.SetResult(frame.Data);
                return; // 模拟服务器处理消息后，确认响应在断链时丢失。
            }
            retrySeen.SetResult(frame.Data);
            await SendResponseAsync(stream, frame.Transaction, "200 OK", token);
            var close = await ReadRelpFrameAsync(stream, token);
            await SendResponseAsync(stream, close.Transaction, "200 OK", token);
        }, connections: 2);
        await using var transport = new SyslogTransport(Target(server.Port, SyslogProtocol.Relp));
        await Assert.ThrowsAsync<IOException>(() => transport.SendAsync(payload));
        Assert.Equal(SyslogDeliveryStage.RelpAcknowledged, (await transport.SendAsync(payload)).Stage);
        Assert.Equal(payload, await firstSeen.Task);
        Assert.Equal(payload, await retrySeen.Task);
    }

    private static SyslogRecord Record() => new(DateTimeOffset.Parse("2026-11-11T01:02:03.1234567Z"), "honeypot-ssh",
        "AUTHENTICATION_ATTEMPTED", SyslogSeverity.Notice, "synthetic-log-1", new Dictionary<string, object?> { ["outcome"] = "rejected_by_policy" });

    private static SyslogTarget Target(int port, SyslogProtocol protocol) => new("test", "Loopback", "127.0.0.1", port, protocol);

    private static JsonDocument ParseBody(byte[] message)
    {
        var text = Encoding.UTF8.GetString(message);
        return JsonDocument.Parse(text[(text.IndexOf(" - \uFEFF", StringComparison.Ordinal) + 4)..]);
    }

    private static X509Certificate2 CreateCertificate()
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=localhost", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var names = new SubjectAlternativeNameBuilder();
        names.AddIpAddress(IPAddress.Loopback);
        names.AddDnsName("localhost");
        request.CertificateExtensions.Add(names.Build());
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddHours(1));
    }

    private static async Task<byte[]> ReadSyslogFrameAsync(Stream stream, CancellationToken token)
    {
        var (lengthText, _) = await ReadTokenAsync(stream, token);
        var length = int.Parse(lengthText, System.Globalization.CultureInfo.InvariantCulture);
        Assert.InRange(length, 1, 8192);
        var payload = new byte[length];
        await stream.ReadExactlyAsync(payload, token);
        return payload;
    }

    private static async Task<(int Transaction, string Command, byte[] Data)> ReadRelpFrameAsync(Stream stream, CancellationToken token)
    {
        var transaction = (await ReadTokenAsync(stream, token)).Value;
        var command = (await ReadTokenAsync(stream, token)).Value;
        var (lengthText, delimiter) = await ReadTokenAsync(stream, token);
        var length = int.Parse(lengthText, System.Globalization.CultureInfo.InvariantCulture);
        Assert.InRange(length, 0, 8192);
        var data = new byte[length];
        if (length > 0)
        {
            await stream.ReadExactlyAsync(data, token);
            var trailer = new byte[1];
            await stream.ReadExactlyAsync(trailer, token);
            Assert.Equal((byte)'\n', trailer[0]);
        }
        else Assert.Equal('\n', delimiter);
        return (int.Parse(transaction, System.Globalization.CultureInfo.InvariantCulture), command, data);
    }

    private static async Task<(string Value, char Delimiter)> ReadTokenAsync(Stream stream, CancellationToken token)
    {
        var value = new StringBuilder();
        var next = new byte[1];
        while (value.Length < 64)
        {
            await stream.ReadExactlyAsync(next, token);
            if (next[0] is (byte)' ' or (byte)'\n') return (value.ToString(), (char)next[0]);
            value.Append((char)next[0]);
        }
        throw new IOException("Synthetic frame too long");
    }

    private static async Task AcceptRelpOpenAsync(Stream stream, CancellationToken token)
    {
        var frame = await ReadRelpFrameAsync(stream, token);
        Assert.Equal("open", frame.Command);
        Assert.Contains("relp_version=0", Encoding.ASCII.GetString(frame.Data));
        Assert.Contains("commands=syslog", Encoding.ASCII.GetString(frame.Data));
        await SendResponseAsync(stream, frame.Transaction, "200 OK\nrelp_version=0\ncommands=syslog", token);
    }

    private static async Task SendResponseAsync(Stream stream, int transaction, string data, CancellationToken token, bool fragmented = false)
    {
        var body = Encoding.UTF8.GetBytes(data);
        var prefix = Encoding.ASCII.GetBytes($"{transaction} rsp {body.Length} ");
        if (fragmented)
        {
            foreach (var value in prefix) await stream.WriteAsync(new[] { value }, token);
        }
        else await stream.WriteAsync(prefix, token);
        await stream.WriteAsync(body, token);
        await stream.WriteAsync(new byte[] { (byte)'\n' }, token);
    }

    private sealed class LoopbackServer : IAsyncDisposable
    {
        private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource _shutdown = new(TimeSpan.FromSeconds(15));
        private readonly Task _run;
        public int Port { get; }

        public LoopbackServer(Func<TcpClient, CancellationToken, Task> serve, int connections = 1)
        {
            _listener.Start();
            Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
            _run = RunAsync(serve, connections);
        }

        private async Task RunAsync(Func<TcpClient, CancellationToken, Task> serve, int connections)
        {
            for (var index = 0; index < connections; index++)
            {
                using var client = await _listener.AcceptTcpClientAsync(_shutdown.Token);
                await serve(client, _shutdown.Token);
            }
        }

        public async ValueTask DisposeAsync()
        {
            await _shutdown.CancelAsync();
            _listener.Stop();
            try { await _run; }
            catch (Exception error) when (error is OperationCanceledException or IOException or SocketException) { }
            _shutdown.Dispose();
        }
    }
}
