namespace Honeypot.Api.Models;

/// <summary>仅提供有实际观测依据的接纳、最后阶段和关闭时间；计数区分观测与可回看明细。</summary>
public sealed record ConnectionTraceSummary(string ConnectionId, string SourceIp, int SourcePort, string DestinationIp,
    int DestinationPort, string AdapterKey, string ListenerId, string ServiceInstanceId, string? AdmissionOutcome,
    string? AdmissionReason, DateTimeOffset? AdmittedAtUtc, string LastStage, DateTimeOffset? ClosedAtUtc,
    string? CloseReason, int ObservedCount, int AvailableCount);
