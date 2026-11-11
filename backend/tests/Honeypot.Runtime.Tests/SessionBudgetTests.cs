using Honeypot.Runtime.Common;
using System.Net;
using System.Net.Sockets;
using Honeypot.Protocol.Abstractions.Models;
using Honeypot.Protocol.Abstractions.Service;
using Honeypot.Runtime.Service;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Honeypot.Runtime.Tests;

public sealed class SessionBudgetTests
{
    [Fact]
    public async Task RawStreamCannotBypassRuntimeBudgetAndLimitIsRecorded()
    {
        using var reservation = new TcpListener(IPAddress.Loopback, 0);
        reservation.Start();
        var port = ((IPEndPoint)reservation.LocalEndpoint).Port;
        reservation.Stop();
        var registry = new ProtocolAdapterRegistry();
        registry.Register(new RawWriterAdapter());
        var events = new InMemoryInteractionEventSink();
        await using var host = new TcpListenerHost(registry, events, new ConnectionIdGenerator(), NullLogger<TcpListenerHost>.Instance);
        var applied = await host.ApplyAsync(new ServiceInstance
        {
            InstanceId = "budget", DisplayName = "isolated budget test", AdapterKey = "budget",
            Profile = new ServiceProfile { ProfileId = "budget", AdapterKey = "budget", MaxFrameBytes = 64, MaxSessionBytes = 64 },
            Bindings = new[] { new ListenerBinding { ListenerId = "budget", BindAddress = "127.0.0.1", Port = port } },
        });
        Assert.True(applied.Succeeded);
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        Assert.Equal(0, await client.GetStream().ReadAsync(new byte[1], timeout.Token));
        while (!events.Events.Any(item => item.EventType == "ResourceLimitExceeded")) await Task.Delay(10, timeout.Token);
        var limited = Assert.Single(events.Events, item => item.EventType == "ResourceLimitExceeded");
        Assert.Equal("transport", limited.Stage);
        Assert.Equal(port, limited.DestinationPort);
    }

    [Fact]
    public async Task ReadAndWriteShareOneBudgetIncludingRawStreamOperations()
    {
        using var network = new MemoryStream(new byte[32], writable: true);
        await using var bounded = new SessionBudgetStream(network, 10);
        Assert.Equal(6, await bounded.ReadAsync(new byte[6]));
        await bounded.WriteAsync(new byte[4]);
        Assert.False(bounded.LimitExceeded);
        await Assert.ThrowsAsync<IOException>(async () => { _ = await bounded.ReadAsync(new byte[1]); });
        Assert.True(bounded.LimitExceeded);
    }

    [Fact]
    public async Task OversizedWriteIsRejectedBeforeSending()
    {
        using var network = new MemoryStream();
        await using var bounded = new SessionBudgetStream(network, 4);
        await Assert.ThrowsAsync<IOException>(async () => await bounded.WriteAsync(new byte[5]));
        Assert.Equal(0, network.Length);
        Assert.True(bounded.LimitExceeded);
    }

    private sealed class RawWriterAdapter : IHoneypotServiceAdapter
    {
        public ServiceAdapterDescriptor Descriptor => new() { AdapterKey = "budget", DisplayName = "Budget test", Version = "1" };
        public ValueTask<AdapterValidationResult> ValidateAsync(ServiceProfile profile, CancellationToken cancellationToken = default) => ValueTask.FromResult(AdapterValidationResult.Valid());
        public ValueTask HandleAsync(IHoneypotSession session, ProtocolSessionContext context, ServiceProfile profile, IInteractionEventSink sink, CancellationToken ct = default) =>
            ((IRawStreamHoneypotSession)session).RawStream.WriteAsync(new byte[65], ct);
    }
}
