using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Honeypot.Api.Models;
using Honeypot.Api.Service.impl;
using Xunit;

namespace Honeypot.Runtime.Tests;

/// <summary>只连接进程内回环 SMTP，使用合成账号；不会向外部邮箱投递。</summary>
public sealed class MailKitTransportTests
{
    [Fact]
    public async Task LoopbackSmtpAcceptsMultipartHtmlAndPlainText()
    {
        await using var server = new LocalSmtpServer();
        var result = await new MailKitTransport().SendAsync(Settings(server.Port, "None"), Message());
        Assert.Equal("Accepted", result.Status);
        var mime = await server.Body.Task.WaitAsync(TimeSpan.FromSeconds(3));
        Assert.Contains("multipart/alternative", mime, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("text/plain", mime, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("text/html", mime, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("synthetic-message@honeypot.local", mime, StringComparison.Ordinal);
        Assert.Contains("AUTH", server.Commands);
        Assert.Contains("DATA", server.Commands);
    }

    [Fact]
    public async Task RequiredStartTlsDoesNotDowngradeOrSendAuthentication()
    {
        await using var server = new LocalSmtpServer();
        var result = await new MailKitTransport().SendAsync(Settings(server.Port, "StartTls"), Message());
        Assert.Equal("Failed", result.Status);
        Assert.Contains("EHLO", server.Commands);
        Assert.DoesNotContain("AUTH", server.Commands);
        Assert.DoesNotContain("DATA", server.Commands);
    }

    [Fact]
    public async Task TotalDeadlineCancelsAStalledServerBeforeSubmission()
    {
        await using var server = new LocalSmtpServer(stall: true);
        var watch = System.Diagnostics.Stopwatch.StartNew();
        var result = await new MailKitTransport().SendAsync(Settings(server.Port, "None") with { TimeoutSeconds = 1 }, Message());
        Assert.Equal("Retrying", result.Status);
        Assert.Equal("SMTP_CONNECTION_FAILED", result.ErrorCode);
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(5));
        Assert.DoesNotContain("AUTH", server.Commands);
    }

    private static NotificationTransportSettings Settings(int port, string mode) => new(true, "127.0.0.1", port, mode,
        "sender@example.test", "Unit Test", "synthetic-user", "synthetic-authorization", 5);
    private static MailTransportMessage Message() => new("reader@example.test", "synthetic-message@honeypot.local",
        "Synthetic SMTP test", "<html><body><h1>Visible report</h1></body></html>", "Visible report");

    private sealed class LocalSmtpServer : IAsyncDisposable
    {
        private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource _shutdown = new();
        private readonly Task _run;
        public int Port { get; }
        public ConcurrentQueue<string> Commands { get; } = new();
        public TaskCompletionSource<string> Body { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public LocalSmtpServer(bool stall = false)
        {
            _listener.Start();
            Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
            _run = ServeAsync(stall, _shutdown.Token);
        }

        private async Task ServeAsync(bool stall, CancellationToken cancellationToken)
        {
            using var client = await _listener.AcceptTcpClientAsync(cancellationToken);
            if (stall)
            {
                await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
                return;
            }
            await using var stream = client.GetStream();
            using var reader = new StreamReader(stream, Encoding.ASCII, leaveOpen: true);
            await using var writer = new StreamWriter(stream, Encoding.ASCII, leaveOpen: true) { NewLine = "\r\n", AutoFlush = true };
            await writer.WriteLineAsync("220 localhost isolated SMTP".AsMemory(), cancellationToken);
            while (await reader.ReadLineAsync(cancellationToken) is { } line)
            {
                var command = line.Split(' ', 2)[0].ToUpperInvariant();
                // 只记录命令名称，不保留 AUTH 参数中的合成凭据。
                Commands.Enqueue(command);
                switch (command)
                {
                    case "EHLO":
                        await writer.WriteLineAsync("250-localhost\r\n250 AUTH PLAIN".AsMemory(), cancellationToken);
                        break;
                    case "AUTH":
                        if (line.Split(' ').Length < 3)
                        {
                            await writer.WriteLineAsync("334 ".AsMemory(), cancellationToken);
                            _ = await reader.ReadLineAsync(cancellationToken);
                        }
                        await writer.WriteLineAsync("235 Authentication successful".AsMemory(), cancellationToken);
                        break;
                    case "MAIL":
                    case "RCPT":
                        await writer.WriteLineAsync("250 OK".AsMemory(), cancellationToken);
                        break;
                    case "DATA":
                        await writer.WriteLineAsync("354 End with period".AsMemory(), cancellationToken);
                        var body = new StringBuilder();
                        while (await reader.ReadLineAsync(cancellationToken) is { } bodyLine && bodyLine != ".") body.AppendLine(bodyLine);
                        Body.TrySetResult(body.ToString());
                        await writer.WriteLineAsync("250 Message accepted".AsMemory(), cancellationToken);
                        break;
                    case "QUIT":
                        await writer.WriteLineAsync("221 Bye".AsMemory(), cancellationToken);
                        return;
                    default:
                        await writer.WriteLineAsync("500 Unsupported command".AsMemory(), cancellationToken);
                        break;
                }
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
