using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using Honeypot.Api.Service;
using Honeypot.Api.Service.impl;
using Honeypot.Api.Workers;
using Honeypot.Shared.Models;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Honeypot.Runtime.Tests;

public sealed class SyslogDeliveryWorkerTests
{
    [Fact]
    public async Task PersistedSettingsForwardAllSeveritiesWithLocal0AndHotDisableWithoutHostnameInBody()
    {
        using var receiver = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var (configuration, environment) = IsolatedEnvironment();
        var initial = new FileSyslogSettingsStore(configuration, environment);
        var target = Target(((IPEndPoint)receiver.Client.LocalEndPoint!).Port) with { IgnoredSeverities = [6], Facility = 20 };
        await initial.SaveAsync(new() { Enabled = true, Targets = [target] }, 0);

        // 用新实例从真实配置文件恢复，测试不通过直接替换 worker 内部状态模拟启动。
        var store = new FileSyslogSettingsStore(configuration, environment);
        Assert.True(store.Current.Settings.Enabled);
        var ids = new TestIds();
        var queue = new SyslogQueue(store, ids, TimeProvider.System);
        using var worker = new SyslogDeliveryWorker(store, queue, ids, TimeProvider.System,
            configuration, environment, NullLogger<SyslogDeliveryWorker>.Instance);
        await worker.StartAsync(CancellationToken.None);
        try
        {
            queue.Publish("honeypot-ssh", "AUTHENTICATION_ATTEMPTED", SyslogSeverity.Notice,
                new Dictionary<string, object?> { ["eventId"] = "isolated-auth", ["username"] = "test-user",
                    ["hostname"] = "untrusted-host", ["displayHost"] = "untrusted-display", ["password"] = "isolated-secret" });
            queue.Publish("honeypot-api", "FORWARDED_INFO", SyslogSeverity.Informational);
            var packet = await Receive(receiver);
            var line = Encoding.UTF8.GetString(packet);
            var header = line.Split(' ', 8);
            Assert.Equal("<133>1", header[0]);
            Assert.Equal(store.Current.Hostname, header[2]);
            Assert.Equal("honeypot-ssh", header[3]);
            using var body = JsonDocument.Parse(header[7].TrimStart('\uFEFF'));
            Assert.Equal("isolated-auth", body.RootElement.GetProperty("eventId").GetString());
            Assert.False(body.RootElement.TryGetProperty("hostname", out _));
            Assert.False(body.RootElement.TryGetProperty("displayHost", out _));
            Assert.False(body.RootElement.TryGetProperty("computerName", out _));
            Assert.DoesNotContain("isolated-secret", line);
            Assert.DoesNotContain("untrusted-host", line);
            var information = Encoding.UTF8.GetString(await Receive(receiver));
            Assert.StartsWith("<134>1 ", information);
            Assert.Contains("FORWARDED_INFO", information);
            await WaitUntil(() => worker.GetStatus().Targets.Single().SentCount == 2);
            var status = worker.GetStatus().Targets.Single();
            Assert.Equal("LocalSubmitted", status.State);
            Assert.Equal(0, status.ConfirmedCount);
            Assert.NotNull(status.LastSentAtUtc);
            await NoPacket(receiver);

            await store.SaveAsync(store.Current.Settings with { Enabled = false }, store.Current.Revision);
            Assert.Equal("Disabled", worker.GetStatus().Targets.Single().State);
            queue.Publish("honeypot-api", "DISABLED_EVENT", SyslogSeverity.Error);
            await NoPacket(receiver);

            // 重新启用后转发各级新日志，关闭期间未采集的日志不会补发。
            await store.SaveAsync(store.Current.Settings with
            { Enabled = true, Targets = [target with { IgnoredSeverities = [5] }] }, store.Current.Revision);
            queue.Publish("honeypot-api", "ENABLED_NOTICE", SyslogSeverity.Notice);
            queue.Publish("honeypot-api", "ENABLED_ERROR", SyslogSeverity.Error);
            Assert.Contains("ENABLED_NOTICE", Encoding.UTF8.GetString(await Receive(receiver)));
            Assert.Contains("ENABLED_ERROR", Encoding.UTF8.GetString(await Receive(receiver)));
            await WaitUntil(() => worker.GetStatus().Targets.Single().SentCount == 4);
            await NoPacket(receiver);
        }
        finally { await worker.StopAsync(CancellationToken.None); }
    }

    [Theory]
    [InlineData(null, "通研蜜罐 Syslog 测试消息")]
    [InlineData("指定的测试消息", "指定的测试消息")]
    public async Task ExplicitTestWhileDisabledSendsOnePacketAndDoesNotEnableRoutineDelivery(string? customMessage, string expectedMessage)
    {
        using var receiver = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var (configuration, environment) = IsolatedEnvironment();
        var store = new FileSyslogSettingsStore(configuration, environment);
        await store.SaveAsync(new() { Targets = [Target(((IPEndPoint)receiver.Client.LocalEndPoint!).Port)] }, 0);
        var ids = new TestIds();
        var queue = new SyslogQueue(store, ids, TimeProvider.System);
        using var worker = new SyslogDeliveryWorker(store, queue, ids, TimeProvider.System,
            configuration, environment, NullLogger<SyslogDeliveryWorker>.Instance);
        await worker.StartAsync(CancellationToken.None);
        try
        {
            queue.Publish("honeypot-api", "MUST_NOT_SEND", SyslogSeverity.Error);
            var oversized = await worker.TestAsync("isolated-target", new string('测', 256));
            Assert.False(oversized.Succeeded);
            Assert.Equal("SYSLOG_TEST_MESSAGE_TOO_LONG", oversized.ErrorCode);
            var test = await worker.TestAsync("isolated-target", customMessage);
            Assert.True(test.Succeeded);
            Assert.Equal("LocalSubmitted", test.Stage);
            var message = Encoding.UTF8.GetString(await Receive(receiver));
            Assert.Contains("SYSLOG_TEST", message);
            Assert.Contains(test.CorrelationId, message);
            using var body = JsonDocument.Parse(message.Split(' ', 8)[7].TrimStart('\uFEFF'));
            Assert.Equal(expectedMessage, body.RootElement.GetProperty("message").GetString());
            Assert.False(store.Current.Settings.Enabled);
            Assert.Equal("Disabled", worker.GetStatus().Targets.Single().State);
            Assert.Equal("SYSLOG_TEST_RATE_LIMITED", (await worker.TestAsync("isolated-target")).ErrorCode);
            await NoPacket(receiver);
        }
        finally { await worker.StopAsync(CancellationToken.None); }
    }

    private static SyslogTarget Target(int port) => new("isolated-target", "isolated", "127.0.0.1", port, SyslogProtocol.Udp);

    [Fact]
    public async Task RestartKeepsPendingRecordBoundToOriginalTargetUntilItsFingerprintIsRestored()
    {
        using var originalReceiver = new TcpListener(IPAddress.Loopback, 0);
        originalReceiver.Start();
        var originalPort = ((IPEndPoint)originalReceiver.LocalEndpoint).Port;
        originalReceiver.Stop();
        using var replacementReceiver = new TcpListener(IPAddress.Loopback, 0);
        replacementReceiver.Start();
        var replacementPort = ((IPEndPoint)replacementReceiver.LocalEndpoint).Port;
        Assert.NotEqual(originalPort, replacementPort);
        var (configuration, environment) = IsolatedEnvironment();
        var initialStore = new FileSyslogSettingsStore(configuration, environment);
        var original = Target(originalPort) with { Protocol = SyslogProtocol.Tcp };
        await initialStore.SaveAsync(new() { Enabled = true, Targets = [original] }, 0);
        var ids = new TestIds();
        var firstQueue = new SyslogQueue(initialStore, ids, TimeProvider.System);
        using (var firstWorker = new SyslogDeliveryWorker(initialStore, firstQueue, ids, TimeProvider.System,
            configuration, environment, NullLogger<SyslogDeliveryWorker>.Instance))
        {
            await firstWorker.StartAsync(CancellationToken.None);
            try
            {
                firstQueue.Publish("honeypot-api", "OLD_DESTINATION_RECORD", SyslogSeverity.Error);
                await WaitUntil(() => firstWorker.GetStatus().Targets.Single() is { PendingCount: 1, FailedCount: > 0 });
            }
            finally { await firstWorker.StopAsync(CancellationToken.None); }
        }

        await initialStore.SaveAsync(initialStore.Current.Settings with
        { Targets = [original with { Port = replacementPort }] }, initialStore.Current.Revision);
        var restoredStore = new FileSyslogSettingsStore(configuration, environment);
        var restoredQueue = new SyslogQueue(restoredStore, ids, TimeProvider.System);
        using var restoredWorker = new SyslogDeliveryWorker(restoredStore, restoredQueue, ids, TimeProvider.System,
            configuration, environment, NullLogger<SyslogDeliveryWorker>.Instance);
        await restoredWorker.StartAsync(CancellationToken.None);
        try
        {
            restoredQueue.Publish("honeypot-api", "NEW_DESTINATION_RECORD", SyslogSeverity.Notice);
            using var connectTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            using var replacementClient = await replacementReceiver.AcceptTcpClientAsync(connectTimeout.Token);
            var replacementMessage = await ReadFrame(replacementClient.GetStream());
            Assert.Contains("NEW_DESTINATION_RECORD", replacementMessage);
            Assert.DoesNotContain("OLD_DESTINATION_RECORD", replacementMessage);
            using (var noExtra = new CancellationTokenSource(TimeSpan.FromMilliseconds(250)))
                await Assert.ThrowsAnyAsync<OperationCanceledException>(() => replacementClient.GetStream().ReadAsync(new byte[1], noExtra.Token).AsTask());

            // 恢复完全相同的目标指纹后，重启前未完成的记录才能继续发给原地址。
            using var reopenedOriginal = new TcpListener(IPAddress.Loopback, originalPort);
            reopenedOriginal.Start();
            await restoredStore.SaveAsync(restoredStore.Current.Settings with { Targets = [original] }, restoredStore.Current.Revision);
            using var originalTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            using var originalClient = await reopenedOriginal.AcceptTcpClientAsync(originalTimeout.Token);
            var replayed = await ReadFrame(originalClient.GetStream());
            Assert.Contains("OLD_DESTINATION_RECORD", replayed);
            Assert.DoesNotContain("NEW_DESTINATION_RECORD", replayed);
            await WaitUntil(() => restoredWorker.GetStatus().Targets.Single() is { PendingCount: 0, SentCount: 1 });
        }
        finally { await restoredWorker.StopAsync(CancellationToken.None); }
    }

    private static async Task<string> ReadFrame(NetworkStream stream)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var digits = new StringBuilder();
        var next = new byte[1];
        while (true)
        {
            await stream.ReadExactlyAsync(next, timeout.Token);
            if (next[0] == ' ') break;
            Assert.InRange(next[0], (byte)'0', (byte)'9');
            Assert.True(digits.Length < 8);
            digits.Append((char)next[0]);
        }
        var body = new byte[int.Parse(digits.ToString(), System.Globalization.CultureInfo.InvariantCulture)];
        await stream.ReadExactlyAsync(body, timeout.Token);
        return Encoding.UTF8.GetString(body);
    }

    private static (IConfiguration Configuration, IHostEnvironment Environment) IsolatedEnvironment()
    {
        var directory = Path.Combine(Path.GetTempPath(), "honeypot-syslog-worker-" + Guid.NewGuid().ToString("N"));
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        { ["Honeypot:DataDirectory"] = directory }).Build();
        return (configuration, new TestEnvironment { ContentRootPath = directory });
    }

    private static async Task<byte[]> Receive(UdpClient receiver)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        return (await receiver.ReceiveAsync(timeout.Token)).Buffer;
    }

    private static async Task NoPacket(UdpClient receiver)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromMilliseconds(250));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => receiver.ReceiveAsync(timeout.Token).AsTask());
    }

    private static async Task WaitUntil(Func<bool> condition)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        while (!condition()) await Task.Delay(10, timeout.Token);
    }

    private sealed class TestIds : IResourceIdGenerator
    {
        private long _next;
        public string NewId() => Interlocked.Increment(ref _next).ToString(System.Globalization.CultureInfo.InvariantCulture);
    }

    private sealed class TestEnvironment : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = Environments.Development;
        public string ApplicationName { get; set; } = "IsolatedSyslogTests";
        public string ContentRootPath { get; set; } = "";
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}
