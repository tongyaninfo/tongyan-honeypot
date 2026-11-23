using System.Net;
using System.Net.Sockets;
using System.Text;
using Honeypot.Api.Options;
using Honeypot.Api.Service.impl;
using Honeypot.Api.Workers;
using Honeypot.Protocol.Abstractions.Models;
using Honeypot.Protocols.Redis;
using Honeypot.Runtime.Options;
using Honeypot.Runtime.Service;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Honeypot.Runtime.Tests;

public sealed partial class CredentialEvidencePersistenceTests
{
    [Fact]
    public async Task TcpClientsReconcileEveryAdmissionAuthenticationAndDurableEvidenceAfterReopen()
    {
        var fixture = await Fixture.CreateAsync();
        var settings = Microsoft.Extensions.Options.Options.Create(new EventStorageOptions());
        var health = new ReportIngestionHealth();
        ReportInteractionEventStore OpenWriter() => new(fixture.Factory, fixture.OpenStore(),
            new SqliteThreatProfileStore(fixture.Factory, settings, fixture.Clock, new ResourceIdGenerator()), health,
            NullLogger<ReportInteractionEventStore>.Instance, options: settings, time: fixture.Clock);
        var store = OpenWriter();
        using var writer = new ReportEventWriterWorker(store);
        await writer.StartAsync(CancellationToken.None);
        var registry = new ProtocolAdapterRegistry();
        registry.Register(new RedisAdapter());
        var limits = Microsoft.Extensions.Options.Options.Create(new ConnectionAdmissionOptions { MaxConcurrentConnections = 1 });
        await using var listener = new TcpListenerHost(registry, store, new ConnectionIdGenerator(),
            NullLogger<TcpListenerHost>.Instance, limits);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var ct = timeout.Token;
        int port;
        using (var address = new TcpListener(IPAddress.Loopback, 0))
        {
            address.Start();
            port = ((IPEndPoint)address.LocalEndpoint).Port;
        }
        var instance = new ServiceInstance
        {
            InstanceId = "trace", DisplayName = "trace", AdapterKey = "redis",
            Profile = new ServiceProfile { ProfileId = "trace-redis", AdapterKey = "redis", HandshakeTimeout = TimeSpan.FromSeconds(1) },
            Bindings = [new ListenerBinding { ListenerId = "trace-tcp", BindAddress = "127.0.0.1", Port = port }],
        };
        Assert.True((await listener.ApplyAsync(instance, ct)).Succeeded);
        using var first = new TcpClient();
        await first.ConnectAsync(IPAddress.Loopback, port, ct);
        var acceptedPort = ((IPEndPoint)first.Client.LocalEndPoint!).Port;
        var stream = first.GetStream();
        using var responses = new StreamReader(stream, Encoding.ASCII, leaveOpen: true);
        var credentials = Encoding.ASCII.GetBytes("AUTH fixture-account fixture-password\r\n");
        await WriteAuthenticationAsync();

        // 第一条会话仍处于活动状态。用客户端的源端口建立独立清单，不能只比较库里的总数。
        int rejectedPort;
        using (var rejected = new TcpClient())
        {
            await rejected.ConnectAsync(IPAddress.Loopback, port, ct);
            rejectedPort = ((IPEndPoint)rejected.Client.LocalEndPoint!).Port;
            Assert.Equal(0, await rejected.GetStream().ReadAsync(new byte[1], ct));
        }
        await WriteAuthenticationAsync();
        await WriteAuthenticationAsync();
        while (listener.GetStatuses().Single().ActiveConnections != 0) await Task.Delay(10, ct);
        int immediatePort;
        using (var immediate = new TcpClient())
        {
            await immediate.ConnectAsync(IPAddress.Loopback, port, ct);
            immediatePort = ((IPEndPoint)immediate.Client.LocalEndPoint!).Port;
        }
        while (store.GetAll().Count(item => item.EventType == "SessionClosed") < 3) await Task.Delay(10, ct);
        while (listener.GetStatuses().Single().ActiveConnections != 0) await Task.Delay(10, ct);
        int handshakeTimeoutPort;
        using (var silent = new TcpClient())
        {
            await silent.ConnectAsync(IPAddress.Loopback, port, ct);
            handshakeTimeoutPort = ((IPEndPoint)silent.Client.LocalEndPoint!).Port;
            Assert.Equal(0, await silent.GetStream().ReadAsync(new byte[1], ct));
        }
        await listener.StopAsync(ct);
        await writer.StopAsync(ct);

        var reopened = OpenWriter();
        var events = reopened.GetAll();
        var sessions = events.GroupBy(item => item.ConnectionId)
            .ToDictionary(group => group.First().SourcePort, group => group.OrderBy(item => item.Sequence).ToArray());
        Assert.Equal(4, sessions.Count);
        Assert.Equal(new[] { "ConnectionAccepted", "AuthenticationAttempted", "AuthenticationAttempted",
            "AuthenticationAttempted", "SessionClosed" }, sessions[acceptedPort].Select(item => item.EventType));
        Assert.Equal(new[] { "ConnectionRejected", "SessionClosed" }, sessions[rejectedPort].Select(item => item.EventType));
        Assert.Equal("global_concurrency", sessions[rejectedPort][0].PayloadSummary);
        Assert.Equal(SessionCloseReason.AdmissionRejected, sessions[rejectedPort][^1].CloseReason);
        Assert.Equal(new[] { "ConnectionAccepted", "SessionClosed" }, sessions[immediatePort].Select(item => item.EventType));
        Assert.Equal(SessionCloseReason.ClientClosed, sessions[immediatePort][^1].CloseReason);
        Assert.Equal(new[] { "ConnectionAccepted", "SessionClosed" }, sessions[handshakeTimeoutPort].Select(item => item.EventType));
        Assert.Equal(SessionCloseReason.HandshakeTimeout, sessions[handshakeTimeoutPort][^1].CloseReason);
        Assert.Equal("timeout", sessions[handshakeTimeoutPort][^1].Outcome);
        Assert.Equal(11, events.Select(item => item.EventId).Distinct().Count());
        foreach (var steps in sessions.Values)
        {
            Assert.All(steps, item => Assert.Equal(port, item.DestinationPort));
            Assert.Equal(Enumerable.Range(1, steps.Length).Select(number => (long)number), steps.Select(item => item.Sequence));
        }
        var attempts = sessions[acceptedPort].Where(item => item.EventType == "AuthenticationAttempted").ToArray();
        var evidence = fixture.OpenStore();
        Assert.Equal(3, evidence.GetAll().Count);
        Assert.Equal(new int?[] { 1, 2, 3 }, attempts.Select(item => item.AuthenticationAttempt));
        foreach (var item in attempts)
        {
            Assert.Equal("WRONGPASS", item.AuthenticationFailureCode);
            Assert.Equal("fixture-account", item.Username);
            var captured = Assert.Single(evidence.GetAll(), row => row.CredentialArtifactId == item.CredentialArtifactId);
            Assert.Equal(item.ConnectionId, captured.ConnectionId);
            Assert.Equal(item.EventId, captured.EventId);
        }
        using var replay = new ReportEventWriterWorker(reopened);
        await replay.StartAsync(ct);
        foreach (var item in events) Assert.True((await reopened.AppendAsync(item, ct)).IsDuplicate);
        await replay.StopAsync(ct);
        Assert.Equal(3, Assert.Single(evidence.GetPasswordBook()).AuthenticationCount);
        Assert.Equal(11, reopened.GetAll().Count);
        Assert.Equal(0, health.RejectedEvents);

        async Task WriteAuthenticationAsync()
        {
            await stream.WriteAsync(credentials, ct);
            Assert.StartsWith("-WRONGPASS ", await responses.ReadLineAsync(ct));
        }
    }
}
