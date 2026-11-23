using Honeypot.Api.Common;
using Honeypot.Protocol.Abstractions.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Honeypot.Api.Data.Models;

/// <summary>一个实际观测的连接一行。缺少接纳或关闭事件时，不推断开始、结束和原因。</summary>
internal sealed class ConnectionSummaryEntity
{
    public string ConnectionId { get; set; } = "";
    public string SourceIp { get; set; } = "";
    public int SourcePort { get; set; }
    public string DestinationIp { get; set; } = "";
    public int DestinationPort { get; set; }
    public string ListenerId { get; set; } = "";
    public string ServiceInstanceId { get; set; } = "";
    public string AdapterKey { get; set; } = "";
    public string? AdmissionEventId { get; set; }
    public string? AdmissionOutcome { get; set; }
    public string? AdmissionReason { get; set; }
    public long? AdmittedAtUtcTicks { get; set; }
    public long? ClosedAtUtcTicks { get; set; }
    public SessionCloseReason? CloseReason { get; set; }
    public long LastReceivedAtUnixMs { get; set; }
    public long LastSequence { get; set; }
    public long LastOccurredAtUtcTicks { get; set; }
    public string LastStage { get; set; } = "";
    public int ObservedCount { get; set; }
    public int AuthenticationActivityCount { get; set; }
    public string RepresentativeId { get; set; } = "";
    public int RepresentativePriority { get; set; }
    public long RepresentativeSequence { get; set; }
    public long RepresentativeUtcTicks { get; set; }

    public void Observe(InteractionEvent item, DateTimeOffset receivedAt)
    {
        var ticks = item.OccurredAtUtc.UtcTicks;
        var type = item.EventType.ToLowerInvariant();
        var admission = type is "connectionaccepted" or "connectionrejected";
        if (ObservedCount == 0 || (admission && AdmittedAtUtcTicks is null))
        {
            SourceIp = item.SourceIp;
            SourcePort = item.SourcePort;
            DestinationIp = item.DestinationIp;
            DestinationPort = item.DestinationPort;
            ListenerId = item.ListenerId;
            ServiceInstanceId = item.ServiceInstanceId;
            AdapterKey = item.AdapterKey;
        }
        if (admission && (AdmittedAtUtcTicks is null || ticks < AdmittedAtUtcTicks))
        {
            AdmissionEventId = item.EventId;
            AdmittedAtUtcTicks = ticks;
            AdmissionOutcome = type == "connectionrejected" ? "rejected" : "accepted";
            AdmissionReason = type == "connectionrejected" ? item.PayloadSummary : null;
        }
        if (type == "sessionclosed" && (ClosedAtUtcTicks is null || ticks >= ClosedAtUtcTicks))
        {
            ClosedAtUtcTicks = ticks;
            CloseReason = item.CloseReason;
        }
        if (type != "sessionclosed" && (ObservedCount == 0 || item.Sequence > LastSequence || item.Sequence == LastSequence && ticks >= LastOccurredAtUtcTicks))
        {
            LastSequence = item.Sequence;
            LastOccurredAtUtcTicks = ticks;
            LastStage = item.Stage;
        }
        LastReceivedAtUnixMs = Math.Max(LastReceivedAtUnixMs, receivedAt.ToUnixTimeMilliseconds());
        var priority = InteractionActivityProjection.Priority(item.EventType);
        if (priority == InteractionActivityProjection.Authentication) AuthenticationActivityCount++;
        // 接纳取最早步骤，异常取最高优先级下的最后步骤；迟到事件也遵守同一排序。
        var order = item.Sequence.CompareTo(RepresentativeSequence);
        if (order == 0) order = ticks.CompareTo(RepresentativeUtcTicks);
        if (priority == InteractionActivityProjection.Accepted) order = -order;
        if (ObservedCount == 0 || priority > RepresentativePriority ||
            priority == RepresentativePriority && (order > 0 || order == 0 && string.CompareOrdinal(item.EventId, RepresentativeId) < 0))
        {
            RepresentativeId = item.EventId;
            RepresentativePriority = priority;
            RepresentativeSequence = item.Sequence;
            RepresentativeUtcTicks = ticks;
        }
        ObservedCount++;
    }
}

internal sealed class ConnectionSummaryConfiguration : IEntityTypeConfiguration<ConnectionSummaryEntity>
{
    public void Configure(EntityTypeBuilder<ConnectionSummaryEntity> entity)
    {
        entity.ToTable("connection_summaries");
        entity.HasKey(row => row.ConnectionId);
        entity.Property(row => row.ConnectionId).UseCollation("NOCASE");
        entity.Property(row => row.SourceIp).UseCollation("NOCASE");
        entity.Property(row => row.AdapterKey).UseCollation("NOCASE");
        entity.HasIndex(row => new { row.AdmissionOutcome, row.AdmittedAtUtcTicks });
        entity.HasIndex(row => new { row.SourceIp, row.AdmittedAtUtcTicks });
        entity.HasIndex(row => row.LastReceivedAtUnixMs);
    }
}
