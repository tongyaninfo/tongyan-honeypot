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

    /// <summary>用同一 ID 提交加密证据和认证结果；无法可靠记录时立即终止当前协议流程。</summary>
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
        return await RecordAccessAsync(sink, authentication, profile, materialType, material, ct);
    }

    protected static async ValueTask<InteractionEvent> RecordAccessAsync(IInteractionEventSink sink, InteractionEvent item,
        ServiceProfile profile, string materialType, ReadOnlyMemory<byte> material, CancellationToken ct)
    {
        item = item with { CredentialMaterialBytes = material.Length };
        var stage = "CredentialCaptureFailed";
        string? storageCode = null;
        try
        {
            if (profile.StoreCredentialEvidence && profile.RecordPassword)
            {
                var evidence = new CredentialEvidence(item.ConnectionId, item.EventId, item.SourceIp, item.AdapterKey,
                    materialType, material, item.OccurredAtUtc, profile.CredentialEvidenceRetentionDays, "utf8-json");
                var saved = await CredentialEventRecording.AppendAsync(sink, item, evidence, ct);
                if (!saved.Result.Recorded)
                {
                    stage = "AuthenticationEventWriteFailed";
                    storageCode = saved.Result.Code;
                    throw new AuthenticationRecordingException(stage);
                }
                return saved.Event;
            }
            stage = "AuthenticationEventWriteFailed";
            if (!(await sink.AppendAsync(item, ct)).Recorded) throw new AuthenticationRecordingException(stage);
            return item;
        }
        catch (Exception error)
        {
            if (error is AuthenticationRecordingException failure) stage = failure.Code;
            using var diagnosticDeadline = new CancellationTokenSource(TimeSpan.FromSeconds(2));
            var diagnosticCt = diagnosticDeadline.Token;
            var reason = storageCode switch
            {
                "SQLITE_FULL" or "SQLITE_BUSY" or "SQLITE_LOCKED" or "SQLITE_READONLY" or "SQLITE_IOERR" or "SQLITE_CANTOPEN" => storageCode,
                _ when error is System.Security.Cryptography.CryptographicException => "EVIDENCE_KEY_UNAVAILABLE",
                _ when error is OperationCanceledException => "EVIDENCE_CONFIRMATION_TIMEOUT",
                _ => "EVIDENCE_CAPTURE_FAILED",
            };
            try
            {
                // 大材料失败时剩余空间可能仍够提交元数据。相同 EventId 令确认超时后的重试保持幂等。
                var fallback = await sink.AppendAsync(item with
                {
                    CredentialArtifactId = null, CredentialCaptureStatus = profile.StoreCredentialEvidence && profile.RecordPassword ? "Failed" : "Disabled",
                    CredentialCaptureError = reason,
                }, diagnosticCt).AsTask().WaitAsync(diagnosticCt);
                if (!fallback.IsDuplicate)
                    await sink.AppendAsync(item with { EventId = Guid.NewGuid().ToString("N"), EventType = stage,
                        CredentialArtifactId = null, CredentialCaptureStatus = "Failed", CredentialCaptureError = reason,
                        Outcome = "storage_failed", RiskDelta = 0, PayloadSummary = "Authentication evidence could not be recorded" },
                        diagnosticCt).AsTask().WaitAsync(diagnosticCt);
            }
            catch (Exception) { /* 诊断失败时禁止输出原始材料及异常正文。 */ }
            if (error is OperationCanceledException && ct.IsCancellationRequested) throw;
            throw new AuthenticationRecordingException(stage);
        }
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
