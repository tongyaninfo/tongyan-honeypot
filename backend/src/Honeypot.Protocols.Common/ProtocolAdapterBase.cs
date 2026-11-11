using System.Net;
using Honeypot.Protocol.Abstractions.Models;
using Honeypot.Protocol.Abstractions.Service;

namespace Honeypot.Protocols.Common;

public abstract class ProtocolAdapterBase : IHoneypotServiceAdapter
{
    public abstract ServiceAdapterDescriptor Descriptor { get; }

    public virtual ValueTask<AdapterValidationResult> ValidateAsync(ServiceProfile profile, CancellationToken cancellationToken = default)
    {
        if (!string.Equals(profile.AdapterKey, Descriptor.AdapterKey, StringComparison.OrdinalIgnoreCase))
            return ValueTask.FromResult(AdapterValidationResult.Invalid("ADAPTER_PROFILE_MISMATCH", "profile adapter does not match"));
        if (!string.Equals(profile.AuthMode, "AlwaysFail", StringComparison.OrdinalIgnoreCase))
            return ValueTask.FromResult(AdapterValidationResult.Invalid("AUTH_MODE_UNSUPPORTED", "only AlwaysFail is supported"));
        if (profile.MaxAuthenticationAttempts is < 1 or > 100 || profile.MaxFrameBytes is < 64 or > 1024 * 1024 ||
            profile.MaxSessionBytes < profile.MaxFrameBytes || profile.HandshakeTimeout <= TimeSpan.Zero ||
            profile.IdleTimeout <= TimeSpan.Zero || profile.CredentialEvidenceRetentionDays is < 1 or > 3650)
            return ValueTask.FromResult(AdapterValidationResult.Invalid("INVALID_RESOURCE_POLICY", "invalid authentication resource limits"));
        return ValueTask.FromResult(AdapterValidationResult.Valid());
    }

    public abstract ValueTask HandleAsync(IHoneypotSession session, ProtocolSessionContext context, ServiceProfile profile,
        IInteractionEventSink eventSink, CancellationToken cancellationToken = default);

    protected static InteractionEvent Event(ProtocolSessionContext c, string type, string stage, string outcome,
        string? summary = null, int risk = 0, string? artifact = null, string? username = null, string? password = null) => new()
    {
        EventId = Guid.NewGuid().ToString("N"), ConnectionId = c.ConnectionId, Sequence = 0,
        EventType = type, OccurredAtUtc = DateTimeOffset.UtcNow, SourceIp = Address(c.RemoteEndPoint),
        SourcePort = Port(c.RemoteEndPoint), DestinationIp = Address(c.LocalEndPoint), DestinationPort = Port(c.LocalEndPoint),
        Transport = "tcp", ListenerId = c.ListenerId, ServiceInstanceId = c.ServiceInstanceId,
        AdapterKey = c.AdapterKey, ProfileId = c.ProfileId, Stage = stage, Outcome = outcome,
        PayloadSummary = summary, Username = username, RiskDelta = risk, CredentialArtifactId = artifact,
        // password 参数仅为旧调用点过渡兼容保留，普通事件绝不保存原文。
    };

    /// <summary>先写加密证据，再追加同一 ID 的失败事件；无法可靠记录时立即终止当前协议流程。</summary>
    protected static async ValueTask<InteractionEvent> RecordAuthenticationAsync(
        IInteractionEventSink sink, ProtocolSessionContext context, ServiceProfile profile, string? username,
        string method, string failureCode, int attempt, string materialType, ReadOnlyMemory<byte> material,
        CancellationToken ct, string? domain = null, string? database = null)
    {
        var authentication = Event(context, "AuthenticationAttempted", "authentication", "failure",
            "Authentication rejected", 5, username: profile.RecordUsername ? username : null) with
        {
            Domain = profile.RecordUsername ? domain : null,
            Database = database,
            AuthenticationMethod = method,
            AuthenticationFailureCode = failureCode,
            AuthenticationAttempt = attempt,
            MaterialType = materialType,
            CredentialCaptureStatus = "Disabled",
        };
        var stage = "CredentialCaptureFailed";
        try
        {
            if (profile.StoreCredentialEvidence && profile.RecordPassword)
            {
                var artifact = await StoreAsync(sink, context, authentication.EventId, materialType, material, profile, ct);
                authentication = authentication with { CredentialArtifactId = artifact, CredentialCaptureStatus = "Captured" };
            }
            stage = "AuthenticationEventWriteFailed";
            var result = await sink.AppendAsync(authentication, ct);
            if (!result.Recorded) throw new AuthenticationRecordingException(stage);
            return authentication;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception)
        {
            // 仅尝试追加固定诊断，不传播原始存储异常、材料或异常堆栈。
            try
            {
                await sink.AppendAsync(Event(context, stage, "authentication", "storage_failed",
                    "Authentication evidence could not be recorded"), ct);
            }
            catch (Exception) { /* 存储已降级，不能再依赖它写出原始异常。 */ }
            throw new AuthenticationRecordingException(stage);
        }
    }

    protected static async ValueTask<string> StoreAsync(IInteractionEventSink sink, ProtocolSessionContext c,
        string eventId, string type, ReadOnlyMemory<byte> material, ServiceProfile p, CancellationToken ct)
    {
        if (sink is not ICredentialEvidenceSink evidenceSink || !p.StoreCredentialEvidence)
            throw new AuthenticationRecordingException("CREDENTIAL_STORE_UNAVAILABLE");
        var artifact = await evidenceSink.StoreAsync(new CredentialEvidence(c.ConnectionId, eventId,
            Address(c.RemoteEndPoint), c.AdapterKey, type, material, DateTimeOffset.UtcNow, p.CredentialEvidenceRetentionDays, "utf8-json"), ct);
        if (string.IsNullOrWhiteSpace(artifact) || artifact.StartsWith("pending-", StringComparison.OrdinalIgnoreCase))
            throw new AuthenticationRecordingException("CREDENTIAL_STORE_UNAVAILABLE");
        return artifact;
    }

    protected static async ValueTask<int> ReadAsync(IHoneypotSession s, Memory<byte> b, TimeSpan timeout, CancellationToken ct)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(timeout);
        try { return await s.ReadAsync(b, deadline.Token); }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { return 0; }
    }

    protected static async ValueTask<byte[]?> ReadFrameAsync(IHoneypotSession session, int maxBytes, int headerBytes,
        Func<byte[], int> lengthParser, TimeSpan timeout, CancellationToken ct)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(timeout);
        try { return await ReadFrameAsync(session, maxBytes, headerBytes, lengthParser, deadline.Token); }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { return null; }
    }

    /// <summary>调用方已有整段握手/请求期限时复用该令牌；取消必须传回适配器，不能竞争后吞成 EOF。</summary>
    protected static async ValueTask<byte[]?> ReadFrameAsync(IHoneypotSession session, int maxBytes, int headerBytes,
        Func<byte[], int> lengthParser, CancellationToken deadline)
    {
        if (headerBytes is < 1 or > 16) throw new ArgumentOutOfRangeException(nameof(headerBytes));
        var header = new byte[headerBytes];
        if (!await ReadExactAsync(session, header, deadline)) return null;
        var length = lengthParser(header);
        if (length < headerBytes || length > maxBytes) return null;
        var frame = new byte[length];
        header.CopyTo(frame, 0);
        if (!await ReadExactAsync(session, frame.AsMemory(headerBytes), deadline)) return null;
        return frame;
    }

    protected static async ValueTask<bool> ReadExactAsync(IHoneypotSession session, Memory<byte> buffer, TimeSpan timeout, CancellationToken ct)
    {
        // 同一帧共享截止时间，不能通过逐字节发送反复刷新超时。
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(timeout);
        try { return await ReadExactAsync(session, buffer, deadline.Token); }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { return false; }
    }

    /// <summary>帧头、帧体和分片共用调用方期限，不为每次读取重新启动计时器。</summary>
    protected static async ValueTask<bool> ReadExactAsync(IHoneypotSession session, Memory<byte> buffer, CancellationToken deadline)
    {
        var offset = 0;
        while (offset < buffer.Length)
        {
            deadline.ThrowIfCancellationRequested();
            var count = await session.ReadAsync(buffer[offset..], deadline);
            deadline.ThrowIfCancellationRequested();
            if (count <= 0) return false;
            offset += count;
        }
        return true;
    }

    protected static string Address(EndPoint e) => e is IPEndPoint ip ? ip.Address.ToString() : e.ToString() ?? "unknown";
    protected static int Port(EndPoint e) => e is IPEndPoint ip ? ip.Port : 0;
}
