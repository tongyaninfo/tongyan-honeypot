using Honeypot.Api.Common;
using Honeypot.Protocol.Abstractions.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using System.Text.Json;

namespace Honeypot.Api.Data.Models;

/// <summary>将查询使用的字段单独建索引，其余脱敏合同一起保存以恢复完整步骤。</summary>
internal sealed class InteractionEventEntity
{
    public string EventId { get; set; } = "";
    public string ConnectionId { get; set; } = "";
    public long Sequence { get; set; }
    public long OccurredAtUtcTicks { get; set; }
    public long ReceivedAtUnixMs { get; set; }
    public long? ShortRetentionUntilUnixMs { get; set; }
    public string SourceIp { get; set; } = "";
    public string AdapterKey { get; set; } = "";
    public string EventType { get; set; } = "";
    public int DestinationPort { get; set; }
    public int ActivityPriority { get; set; }
    public string EventJson { get; set; } = "";

    public static InteractionEventEntity FromSanitized(InteractionEvent item, DateTimeOffset receivedAt, int handshakeRetentionHours = 48) => new()
    {
        EventId = item.EventId, ConnectionId = item.ConnectionId, Sequence = item.Sequence,
        OccurredAtUtcTicks = item.OccurredAtUtc.UtcTicks, ReceivedAtUnixMs = receivedAt.ToUnixTimeMilliseconds(),
        SourceIp = item.SourceIp, AdapterKey = item.AdapterKey, EventType = item.EventType, DestinationPort = item.DestinationPort,
        ActivityPriority = InteractionActivityProjection.Priority(item.EventType),
        ShortRetentionUntilUnixMs = IsRoutineHandshake(item) ? receivedAt.AddHours(handshakeRetentionHours).ToUnixTimeMilliseconds() : null,
        EventJson = JsonSerializer.Serialize(item with { OccurredAtUtc = item.OccurredAtUtc.ToUniversalTime() }),
    };

    // 仅缩短明确识别为正常且未关联证据的握手步骤；未知扩展和异常默认保留。
    private static bool IsRoutineHandshake(InteractionEvent item) =>
        !item.CaptureTruncated && item.CredentialArtifactId is null && item.ProtocolErrorCode is null &&
        item.AuthenticationFailureCode is null && item.RuleVersion is null &&
        (item.Outcome.ToLowerInvariant() is "sent" or "observed" or "completed" or "recorded") &&
        (item.EventType.ToLowerInvariant() is "bannersent" or "handshakereceived" or "x224connectionconfirmsent"
            or "tlshandshakecompleted" or "credsspchallengesent" or "preloginresponsesent");

    public static InteractionEvent Read(string json) => JsonSerializer.Deserialize<InteractionEvent>(json)
        ?? throw new InvalidDataException("INVALID_INTERACTION_EVENT");
}

internal sealed class InteractionEventConfiguration : IEntityTypeConfiguration<InteractionEventEntity>
{
    public void Configure(EntityTypeBuilder<InteractionEventEntity> entity)
    {
        entity.ToTable("interaction_events");
        entity.HasKey(item => item.EventId);
        entity.Property(item => item.EventId).HasMaxLength(128).UseCollation("NOCASE");
        entity.Property(item => item.ConnectionId).HasMaxLength(128).UseCollation("NOCASE");
        entity.Property(item => item.SourceIp).HasMaxLength(64).UseCollation("NOCASE");
        entity.Property(item => item.AdapterKey).HasMaxLength(64).UseCollation("NOCASE");
        entity.Property(item => item.EventType).HasMaxLength(64).UseCollation("NOCASE");
        entity.HasIndex(item => item.ReceivedAtUnixMs);
        entity.HasIndex(item => item.ShortRetentionUntilUnixMs).HasFilter("\"ShortRetentionUntilUnixMs\" IS NOT NULL");
        entity.HasIndex(item => new { item.OccurredAtUtcTicks, item.Sequence });
        entity.HasIndex(item => new { item.ConnectionId, item.Sequence, item.OccurredAtUtcTicks });
        entity.HasIndex(item => new { item.SourceIp, item.OccurredAtUtcTicks });
        entity.HasIndex(item => new { item.AdapterKey, item.OccurredAtUtcTicks });
        entity.HasIndex(item => new { item.DestinationPort, item.OccurredAtUtcTicks });
        entity.HasIndex(item => new { item.EventType, item.OccurredAtUtcTicks });
    }
}
