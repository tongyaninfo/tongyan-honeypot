using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using Honeypot.Api.Common;
using Honeypot.Api.Models;
using Honeypot.Api.Service;
using Honeypot.Api.Service.impl;
using Honeypot.Engine.Service.impl;
using Honeypot.Protocol.Abstractions.Models;
using Honeypot.Protocol.Abstractions.Service;
using Honeypot.Protocols.Common;
using Honeypot.Runtime.Service;
using Honeypot.Shared.Models;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Honeypot.Runtime.Tests;

public sealed class SyslogInteractionTests
{
    [Theory]
    [InlineData("ssh", "honeypot-ssh")]
    [InlineData("rdp", "honeypot-rdp")]
    [InlineData("mysql", "honeypot-mysql")]
    [InlineData("mssql", "honeypot-mssql")]
    [InlineData("mongo", "honeypot-mongodb")]
    [InlineData("postgresql", "honeypot-postgresql")]
    [InlineData("redis", "honeypot-redis")]
    [InlineData("oracle", "honeypot-oracle")]
    [InlineData("db2", "honeypot-db2")]
    [InlineData("memcached", "honeypot-memcached")]
    [InlineData("hbase", "honeypot-hbase")]
    [InlineData("influxdb", "honeypot-influxdb")]
    [InlineData("elasticsearch", "honeypot-elasticsearch")]
    [InlineData("telnet", "honeypot-telnet")]
    [InlineData("smb", "honeypot-smb")]
    [InlineData("nfs", "honeypot-nfs")]
    public void AlwaysFailKeepsNoticeEvenWithHighRiskAndUsesProtocolApplication(string adapter, string app)
    {
        var value = Event() with { AdapterKey = adapter, RiskDelta = 100 };
        Assert.Equal(SyslogSeverity.Notice, SyslogInteractionProjection.Severity(value));
        Assert.Equal(app, SyslogInteractionProjection.AppName(adapter));
    }

    [Fact]
    public void ProjectionKeepsAuthenticationMetadataButNeverRawEvidenceOrSummary()
    {
        var value = Event() with { Password = "isolated-secret", PayloadSummary = "isolated-secret",
            Domain = "test-domain", Database = "test-db", MaterialType = "Response", CredentialCaptureStatus = "Captured" };
        var fields = SyslogInteractionProjection.Fields(value);
        Assert.DoesNotContain("isolated-secret", JsonSerializer.Serialize(fields));
        Assert.Equal("test-user", fields["username"]);
        Assert.Equal("test-domain", fields["domain"]);
        Assert.Equal("Response", fields["materialType"]);
        Assert.Equal(value.OccurredAtUtc, fields["occurredAtUtc"]);
    }

    [Theory]
    [InlineData(SessionCloseReason.StorageDegraded, SyslogSeverity.Error)]
    [InlineData(SessionCloseReason.InternalError, SyslogSeverity.Error)]
    [InlineData(SessionCloseReason.ResourceLimitExceeded, SyslogSeverity.Warning)]
    [InlineData(SessionCloseReason.HandshakeTimeout, SyslogSeverity.Debug)]
    [InlineData(SessionCloseReason.ListenerStopping, SyslogSeverity.Debug)]
    [InlineData(SessionCloseReason.AdapterCompleted, SyslogSeverity.Informational)]
    public void FinalCloseSeverityUsesActualReason(SessionCloseReason closeReason, SyslogSeverity expected)
    {
        Assert.Equal(expected, SyslogInteractionProjection.Severity(Event() with
        { EventType = "SessionClosed", CloseReason = closeReason }));
    }

    [Fact]
    public async Task DuplicateEventDoesNotRepeatProjectionBroadcastOrThreatAggregation()
    {
        var publisher = new RecordingPublisher();
        using var evidence = new InMemoryCredentialEvidenceStore();
        var threats = new InMemoryThreatProfileStore();
        var store = new InMemoryInteractionEventStore(threats, evidence, publisher);
        var notifier = new RecordingNotifier();
        var sink = new RealtimeInteractionEventSink(store, store, notifier, NullLogger<RealtimeInteractionEventSink>.Instance, publisher);
        Assert.False((await sink.AppendAsync(Event())).IsDuplicate);
        var repeated = await sink.AppendAsync(Event());
        Assert.True(repeated.Recorded);
        Assert.True(repeated.IsDuplicate);
        Assert.Single(publisher.Items, item => item.Code == "AuthenticationAttempted");
        Assert.Equal(1, notifier.Events);
        Assert.Equal(1, threats.GetByIp("192.0.2.10")!.AuthenticationAttemptCount);
    }

    [Fact]
    public async Task BrokenSyslogCannotChangeAcceptedEventOrPreventRealtimeNotification()
    {
        var publisher = new RecordingPublisher { Throw = true };
        using var evidence = new InMemoryCredentialEvidenceStore(syslog: publisher);
        var store = new InMemoryInteractionEventStore(new InMemoryThreatProfileStore(), evidence, publisher);
        var notifier = new RecordingNotifier();
        var sink = new RealtimeInteractionEventSink(store, store, notifier, NullLogger<RealtimeInteractionEventSink>.Instance, publisher);
        Assert.True((await sink.AppendAsync(Event())).Recorded);
        Assert.Equal(1, notifier.Events);
    }

    [Fact]
    public void EvidenceReadFailureStillAuditsWithoutLeakingExceptionContent()
    {
        var publisher = new RecordingPublisher();
        var service = new CredentialEvidenceAccessService(new FailingEvidenceStore(), publisher);
        var result = service.Read("cred-test", new AuthenticatedUser("admin", "admin", ["Administrator"]));
        Assert.Equal(500, result.StatusCode);
        Assert.Equal("EVIDENCE_READ_FAILED", Assert.Single(service.GetAuditTrail()).Outcome);
        var audit = Assert.Single(publisher.Items);
        Assert.Equal(SyslogSeverity.Error, audit.Severity);
        Assert.DoesNotContain("isolated-secret", JsonSerializer.Serialize(audit.Fields));
    }

    [Fact]
    public async Task SuspiciousTransitionIsLoggedOnceWithoutCriticalEscalation()
    {
        var publisher = new RecordingPublisher();
        using var evidence = new InMemoryCredentialEvidenceStore();
        var store = new InMemoryInteractionEventStore(new InMemoryThreatProfileStore(), evidence, publisher);
        await store.AppendAsync(Event() with { RiskDelta = 100 });
        await store.AppendAsync(Event() with { EventId = "second-event", RiskDelta = 100 });
        var transition = Assert.Single(publisher.Items, item => item.Code == "THREAT_STATUS_CHANGED");
        Assert.Equal(SyslogSeverity.Notice, transition.Severity);
        Assert.Equal("Suspicious", transition.Fields!["state"]);
    }

    [Theory]
    [InlineData(SessionCloseReason.AdapterCompleted, false)]
    [InlineData(SessionCloseReason.StorageDegraded, false)]
    [InlineData(SessionCloseReason.ProtocolViolation, false)]
    [InlineData(SessionCloseReason.StorageDegraded, true)]
    public async Task RuntimeProducesOneFinalEventWithActualAdapterReason(SessionCloseReason reason, bool throwAfterClose)
    {
        // 仅在回环建立一个合成适配器连接，不运行真实协议服务或接触运行配置。
        var registry = new ProtocolAdapterRegistry();
        registry.Register(new ClosingAdapter(reason, throwAfterClose));
        var events = new InMemoryInteractionEventSink();
        await using var host = new TcpListenerHost(registry, events, new ConnectionIdGenerator(), NullLogger<TcpListenerHost>.Instance);
        var port = FreePort();
        Assert.True((await host.ApplyAsync(Instance(port))).Succeeded);
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        while (!events.Events.Any(item => item.EventType == "SessionClosed")) await Task.Delay(10, deadline.Token);
        var closed = Assert.Single(events.Events, item => item.EventType == "SessionClosed");
        Assert.Equal(reason, closed.CloseReason);
        if (reason != SessionCloseReason.AdapterCompleted) Assert.NotEqual("completed", closed.Outcome);
    }

    [Fact]
    public async Task RejectedConnectionStillGetsStorageDegradedCloseResult()
    {
        var registry = new ProtocolAdapterRegistry();
        var adapter = new ClosingAdapter(SessionCloseReason.AdapterCompleted, false);
        registry.Register(adapter);
        var sink = new RejectAcceptedSink();
        await using var host = new TcpListenerHost(registry, sink, new ConnectionIdGenerator(), NullLogger<TcpListenerHost>.Instance);
        var port = FreePort();
        Assert.True((await host.ApplyAsync(Instance(port))).Succeeded);
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port);
        var closed = await sink.Closed.Task.WaitAsync(TimeSpan.FromSeconds(3));
        Assert.Equal(SessionCloseReason.StorageDegraded, closed.CloseReason);
        Assert.Equal("storage_failed", closed.Outcome);
        Assert.False(adapter.Invoked);
    }

    private static InteractionEvent Event() => new()
    {
        EventId = "test-event", ConnectionId = "test-connection", Sequence = 2, EventType = "AuthenticationAttempted",
        OccurredAtUtc = DateTimeOffset.Parse("2026-11-11T01:00:00Z"), SourceIp = "192.0.2.10", DestinationIp = "192.0.2.20",
        SourcePort = 12345, DestinationPort = 2222, AdapterKey = "ssh", ProfileId = "profile", ListenerId = "listener",
        ServiceInstanceId = "instance", Username = "test-user", Outcome = "failure", AuthenticationMethod = "password",
        AuthenticationFailureCode = "AUTH_FAILED", AuthenticationAttempt = 1,
    };

    [Fact]
    public async Task EofIsRecordedAsClientClosedAndStoppingWaitsForFinalEvent()
    {
        var registry = new ProtocolAdapterRegistry();
        registry.Register(new ReadingAdapter());
        var sink = new SlowCloseSink();
        await using var host = new TcpListenerHost(registry, sink, new ConnectionIdGenerator(), NullLogger<TcpListenerHost>.Instance);
        var port = FreePort();
        Assert.True((await host.ApplyAsync(Instance(port))).Succeeded);
        using (var client = new TcpClient())
        {
            await client.ConnectAsync(IPAddress.Loopback, port);
            client.Client.Shutdown(SocketShutdown.Send);
            var closed = await sink.Closed.Task.WaitAsync(TimeSpan.FromSeconds(3));
            Assert.Equal(SessionCloseReason.ClientClosed, closed.CloseReason);
        }

        var stopSink = new SlowCloseSink();
        var stopRegistry = new ProtocolAdapterRegistry();
        stopRegistry.Register(new ReadingAdapter());
        await using var stopHost = new TcpListenerHost(stopRegistry, stopSink, new ConnectionIdGenerator(), NullLogger<TcpListenerHost>.Instance);
        var stopPort = FreePort();
        Assert.True((await stopHost.ApplyAsync(Instance(stopPort))).Succeeded);
        using var activeClient = new TcpClient();
        await activeClient.ConnectAsync(IPAddress.Loopback, stopPort);
        await stopSink.Accepted.Task.WaitAsync(TimeSpan.FromSeconds(3));
        await stopHost.StopAsync();
        Assert.True(stopSink.Closed.Task.IsCompletedSuccessfully);
        Assert.Equal(SessionCloseReason.ListenerStopping, (await stopSink.Closed.Task).CloseReason);
    }

    private static ServiceInstance Instance(int port) => new()
    {
        InstanceId = "syslog-close-test", DisplayName = "isolated", AdapterKey = "test",
        Profile = new ServiceProfile { ProfileId = "profile", AdapterKey = "test" },
        Bindings = [new ListenerBinding { ListenerId = "listener", BindAddress = "127.0.0.1", Port = port }],
    };

    private static int FreePort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }

    private sealed class ClosingAdapter(SessionCloseReason reason, bool throwAfterClose) : IHoneypotServiceAdapter
    {
        public bool Invoked { get; private set; }
        public ServiceAdapterDescriptor Descriptor => new() { AdapterKey = "test", DisplayName = "isolated", Version = "1" };
        public ValueTask<AdapterValidationResult> ValidateAsync(ServiceProfile profile, CancellationToken cancellationToken = default) => ValueTask.FromResult(AdapterValidationResult.Valid());
        public async ValueTask HandleAsync(IHoneypotSession session, ProtocolSessionContext context, ServiceProfile profile, IInteractionEventSink eventSink, CancellationToken cancellationToken = default)
        {
            Invoked = true;
            await session.CloseAsync(throwAfterClose ? SessionCloseReason.AdapterCompleted : reason);
            if (throwAfterClose) throw new AuthenticationRecordingException("CREDENTIAL_CAPTURE_FAILED");
        }
    }

    private sealed class RejectAcceptedSink : IInteractionEventSink
    {
        public TaskCompletionSource<InteractionEvent> Closed { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public ValueTask<EventAppendResult> AppendAsync(InteractionEvent interactionEvent, CancellationToken cancellationToken = default)
        {
            if (interactionEvent.EventType == "ConnectionAccepted") return ValueTask.FromResult(EventAppendResult.DegradedResult("TEST_UNAVAILABLE", "isolated"));
            if (interactionEvent.EventType == "SessionClosed") Closed.TrySetResult(interactionEvent);
            return ValueTask.FromResult(EventAppendResult.Accepted());
        }
    }

    private sealed class RecordingPublisher : ISyslogPublisher
    {
        public bool Throw { get; init; }
        public ConcurrentQueue<(string App, string Code, SyslogSeverity Severity, IReadOnlyDictionary<string, object?>? Fields)> Items { get; } = new();
        public void Publish(string appName, string eventCode, SyslogSeverity severity, IReadOnlyDictionary<string, object?>? fields = null)
        {
            if (Throw) throw new IOException("isolated-publisher-failure");
            Items.Enqueue((appName, eventCode, severity, fields));
        }
    }

    private sealed class ReadingAdapter : IHoneypotServiceAdapter
    {
        public ServiceAdapterDescriptor Descriptor => new() { AdapterKey = "test", DisplayName = "isolated", Version = "1" };
        public ValueTask<AdapterValidationResult> ValidateAsync(ServiceProfile profile, CancellationToken cancellationToken = default) => ValueTask.FromResult(AdapterValidationResult.Valid());
        public async ValueTask HandleAsync(IHoneypotSession session, ProtocolSessionContext context, ServiceProfile profile, IInteractionEventSink eventSink, CancellationToken cancellationToken = default)
        {
            await session.ReadAsync(new byte[1], cancellationToken);
            await session.CloseAsync(SessionCloseReason.AdapterCompleted);
        }
    }

    private sealed class SlowCloseSink : IInteractionEventSink
    {
        public TaskCompletionSource Accepted { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource<InteractionEvent> Closed { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public async ValueTask<EventAppendResult> AppendAsync(InteractionEvent interactionEvent, CancellationToken cancellationToken = default)
        {
            if (interactionEvent.EventType == "ConnectionAccepted") Accepted.TrySetResult();
            if (interactionEvent.EventType == "SessionClosed")
            {
                await Task.Delay(100, cancellationToken);
                Closed.TrySetResult(interactionEvent);
            }
            return EventAppendResult.Accepted();
        }
    }

    private sealed class RecordingNotifier : IRealtimeUpdateNotifier
    {
        public int Events { get; private set; }
        public Task PublishEventAsync(InteractionEvent interactionEvent, CancellationToken cancellationToken = default) { Events++; return Task.CompletedTask; }
        public Task PublishRuntimeAsync(IReadOnlyCollection<ListenerRuntimeStatus> statuses, CancellationToken cancellationToken = default) => Task.CompletedTask;
    }

    private sealed class FailingEvidenceStore : ICredentialEvidenceStore
    {
        public CredentialEvidenceView? Get(string credentialArtifactId) => throw new IOException("isolated-secret");
        public IReadOnlyCollection<CredentialEvidenceSummary> GetAll() => [];
        public Task<CredentialEvidenceSummary> SaveAsync(string connectionId, string eventId, string sourceIp, string adapterKey,
            string materialType, string content, int retentionDays, CancellationToken cancellationToken = default) => throw new NotSupportedException();
    }
}
