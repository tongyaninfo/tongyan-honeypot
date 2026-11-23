using Honeypot.Protocol.Abstractions.Models;
using Honeypot.Protocol.Abstractions.Service;

namespace Honeypot.Protocols.Common;

public sealed record CredentialEvidence(string ConnectionId, string EventId, string SourceIp, string AdapterKey,
    string MaterialType, ReadOnlyMemory<byte> Content, DateTimeOffset CapturedAtUtc, int RetentionDays,
    string ContentEncoding = "binary");

public interface ICredentialEvidenceSink
{
    ValueTask<string> StoreAsync(CredentialEvidence evidence, CancellationToken cancellationToken = default);
}

public sealed record CredentialEventResult(InteractionEvent Event, EventAppendResult Result);

/// <summary>正式采集路径将事件与证据作为同一项提交，只返回已经落盘的引用。</summary>
public interface ICredentialEventSink
{
    ValueTask<CredentialEventResult> AppendWithEvidenceAsync(InteractionEvent item, CredentialEvidence evidence,
        CancellationToken cancellationToken = default);
}

public static class CredentialEventRecording
{
    public static async ValueTask<CredentialEventResult> AppendAsync(IInteractionEventSink sink, InteractionEvent item,
        CredentialEvidence evidence, CancellationToken cancellationToken = default)
    {
        if (sink is ICredentialEventSink atomic)
            return await atomic.AppendWithEvidenceAsync(item, evidence, cancellationToken);

        // 兼容独立协议记录器；生产监听链始终提供上述事务接口。
        if (sink is not ICredentialEvidenceSink legacy) throw new AuthenticationRecordingException("CredentialCaptureFailed");
        var artifact = await legacy.StoreAsync(evidence, cancellationToken);
        if (string.IsNullOrWhiteSpace(artifact) || artifact.StartsWith("pending-", StringComparison.OrdinalIgnoreCase))
            throw new AuthenticationRecordingException("CredentialCaptureFailed");
        var captured = item with { CredentialArtifactId = artifact, CredentialCaptureStatus = "Captured" };
        return new(captured, await sink.AppendAsync(captured, cancellationToken));
    }
}
