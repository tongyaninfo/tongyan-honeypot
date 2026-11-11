using System.Net;
using System.Text;
using System.Text.Json;
using Honeypot.Protocol.Abstractions.Models;
using Honeypot.Protocol.Abstractions.Service;
using Honeypot.Protocols.Common;
using Xunit;

namespace Honeypot.Protocols.Tests;

public sealed class AuthenticationRecordingTests
{
    private static readonly ProtocolSessionContext Context = new("conn", "listener", "instance", "probe", "profile",
        new IPEndPoint(IPAddress.Parse("192.0.2.10"), 50000), new IPEndPoint(IPAddress.Loopback, 12345), DateTimeOffset.UtcNow);
    private static ServiceProfile Profile => new() { AdapterKey = "probe", ProfileId = "profile" };

    [Fact]
    public async Task CredentialAndFailureEventShareIdAndKeepMaterialOutOfPublicJson()
    {
        var sink = new RecordingSink();
        var result = await ProbeAdapter.Record(sink, Profile);
        var evidence = Assert.Single(sink.Evidence);
        var recorded = Assert.Single(sink.Events);
        Assert.Equal(recorded.EventId, evidence.EventId);
        Assert.Equal(Context.ConnectionId, evidence.ConnectionId);
        Assert.Equal("cred-test", recorded.CredentialArtifactId);
        Assert.Equal("Captured", result.CredentialCaptureStatus);
        Assert.Equal("password", result.AuthenticationMethod);
        Assert.Equal("failure", result.Outcome);
        Assert.Equal(1, result.AuthenticationAttempt);
        Assert.Equal("utf8-json", evidence.ContentEncoding);
        Assert.Contains("isolated-sample-password", Encoding.UTF8.GetString(evidence.Content.Span));
        var json = JsonSerializer.Serialize(result);
        Assert.DoesNotContain("isolated-sample-password", json);
        Assert.Null(result.Password);
    }

    [Fact]
    public async Task StorageExceptionNeverLeaksOriginalMessageOrCreatesSuccessReference()
    {
        var sink = new RecordingSink { FailEvidence = true };
        var error = await Assert.ThrowsAsync<AuthenticationRecordingException>(() => ProbeAdapter.Record(sink, Profile).AsTask());
        Assert.Equal("CredentialCaptureFailed", error.Code);
        Assert.DoesNotContain("isolated-sample-password", error.ToString());
        Assert.Contains(sink.Events, item => item.EventType == "CredentialCaptureFailed");
        Assert.DoesNotContain(sink.Events, item => item.EventType == "AuthenticationAttempted");
        Assert.All(sink.Events, item => Assert.Null(item.CredentialArtifactId));
    }

    [Fact]
    public async Task FailedEventAppendStopsAuthentication()
    {
        var sink = new RecordingSink { RejectEvents = true };
        var error = await Assert.ThrowsAsync<AuthenticationRecordingException>(() => ProbeAdapter.Record(sink, Profile).AsTask());
        Assert.Equal("AuthenticationEventWriteFailed", error.Code);
    }

    [Fact]
    public async Task SinkWithoutEvidenceSupportIsNotReportedAsCaptured()
    {
        await Assert.ThrowsAsync<AuthenticationRecordingException>(() => ProbeAdapter.Record(new EventOnlySink(), Profile).AsTask());
    }

    [Theory]
    [InlineData(false, true)]
    [InlineData(true, false)]
    public async Task DisabledCaptureHasNoArtifact(bool recordPassword, bool storeEvidence)
    {
        var sink = new RecordingSink();
        var result = await ProbeAdapter.Record(sink, Profile with { RecordPassword = recordPassword, StoreCredentialEvidence = storeEvidence, RecordUsername = false });
        Assert.Empty(sink.Evidence);
        Assert.Null(result.CredentialArtifactId);
        Assert.Null(result.Username);
        Assert.Null(result.Domain);
        Assert.Equal("Disabled", result.CredentialCaptureStatus);
    }

    [Fact]
    public void LegacyPasswordPropertyIsNeverSerialized()
    {
        var value = new InteractionEvent { EventId = "evt", ConnectionId = "conn", EventType = "AuthenticationAttempted",
            SourceIp = "192.0.2.10", DestinationIp = "127.0.0.1", ListenerId = "listener", ServiceInstanceId = "instance",
            AdapterKey = "probe", ProfileId = "profile", Password = "isolated-sample-password" };
        Assert.DoesNotContain("isolated-sample-password", JsonSerializer.Serialize(value));
    }

    private sealed class ProbeAdapter : ProtocolAdapterBase
    {
        public override ServiceAdapterDescriptor Descriptor => new() { AdapterKey = "probe", DisplayName = "Probe", Version = "1" };
        public override ValueTask HandleAsync(IHoneypotSession session, ProtocolSessionContext context, ServiceProfile profile, IInteractionEventSink eventSink, CancellationToken cancellationToken = default) => ValueTask.CompletedTask;
        public static ValueTask<InteractionEvent> Record(IInteractionEventSink sink, ServiceProfile profile) => RecordAuthenticationAsync(
            sink, Context, profile, "test-user", "password", "AUTH_FAILED", 1, "Plaintext",
            Encoding.UTF8.GetBytes("{\"password\":\"isolated-sample-password\"}"), CancellationToken.None, domain: "EXAMPLE");
    }

    private sealed class EventOnlySink : IInteractionEventSink
    {
        public ValueTask<EventAppendResult> AppendAsync(InteractionEvent item, CancellationToken ct = default) => ValueTask.FromResult(EventAppendResult.Accepted());
    }

    private sealed class RecordingSink : IInteractionEventSink, ICredentialEvidenceSink
    {
        public bool FailEvidence { get; init; }
        public bool RejectEvents { get; init; }
        public List<InteractionEvent> Events { get; } = new();
        public List<CredentialEvidence> Evidence { get; } = new();
        public ValueTask<EventAppendResult> AppendAsync(InteractionEvent item, CancellationToken ct = default)
        {
            Events.Add(item);
            return ValueTask.FromResult(RejectEvents ? EventAppendResult.DegradedResult("TEST_FAILURE", "test") : EventAppendResult.Accepted());
        }
        public ValueTask<string> StoreAsync(CredentialEvidence evidence, CancellationToken ct = default)
        {
            if (FailEvidence) throw new InvalidOperationException("isolated-sample-password");
            Evidence.Add(evidence);
            return ValueTask.FromResult("cred-test");
        }
    }
}
