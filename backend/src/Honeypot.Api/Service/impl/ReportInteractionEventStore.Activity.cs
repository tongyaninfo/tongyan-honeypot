using System.Text.Json;
using Honeypot.Api.Data;
using Honeypot.Api.Models;
using Honeypot.Protocol.Abstractions.Models;
using Microsoft.EntityFrameworkCore;

namespace Honeypot.Api.Service.impl;

public sealed partial class ReportInteractionEventStore
{
    private sealed record ActivityPageKey(string EventId, int Observed, bool CloseObserved, long OccurredAtUtcTicks, long Sequence);

    private static QueryPageResult<RealtimeInteractionEvent> ReadRecentActivityPage(HoneypotDbContext db,
        long detailCutoff, long now, int page, int size, long offset)
    {
        // 每个代表来自其连接自身的事件，事件 ID 在全库按 NOCASE 唯一。归并代表与主键索引，
        // 一次顺读排除已物理清理的代表。下方两个时间范围互斥，逻辑过期只扣除一次。
        var count = db.Database.SqlQuery<int>($"""
            WITH representatives AS (
                SELECT RepresentativeId COLLATE NOCASE AS EventKey FROM connection_summaries WHERE AuthenticationActivityCount=0
                INTERSECT SELECT EventId FROM interaction_events
                ORDER BY EventKey
            ), expired AS (
                SELECT EventId,ConnectionId,ActivityPriority FROM interaction_events
                WHERE ReceivedAtUnixMs<={detailCutoff}
                UNION ALL
                SELECT EventId,ConnectionId,ActivityPriority FROM interaction_events
                WHERE ShortRetentionUntilUnixMs<={now} AND ReceivedAtUnixMs>{detailCutoff}
            )
            SELECT
                (SELECT COUNT(*) FROM interaction_events WHERE EventType IN ('AuthenticationAttempted','AuthorizationDenied')) +
                (SELECT COUNT(*) FROM representatives) -
                (SELECT COUNT(*) FROM expired e WHERE e.ActivityPriority=4 OR EXISTS (
                    SELECT 1 FROM connection_summaries s WHERE s.ConnectionId=e.ConnectionId
                    AND s.AuthenticationActivityCount=0 AND s.RepresentativeId=e.EventId))
                AS Value
            """).AsEnumerable().Single();
        if (offset >= count) return new([], count, page, size);

        // 利用时间索引从尾端读够一页。同一时刻且序号相同时使用 ID 的二进制顺序。
        var keys = db.Database.SqlQuery<ActivityPageKey>($"""
            SELECT e.EventId,s.ObservedCount AS Observed,(s.ClosedAtUtcTicks IS NOT NULL) AS CloseObserved,
                   e.OccurredAtUtcTicks,e.Sequence
            FROM interaction_events e INDEXED BY IX_interaction_events_OccurredAtUtcTicks_Sequence
            JOIN connection_summaries s ON s.ConnectionId=e.ConnectionId
            WHERE (e.ActivityPriority=4 OR (s.AuthenticationActivityCount=0 AND s.RepresentativeId=e.EventId))
                AND e.ReceivedAtUnixMs>{detailCutoff}
                AND (e.ShortRetentionUntilUnixMs IS NULL OR e.ShortRetentionUntilUnixMs>{now})
            ORDER BY e.OccurredAtUtcTicks DESC,e.Sequence DESC,e.EventId COLLATE BINARY
            LIMIT {size} OFFSET {offset}
            """).ToArray();
        return new(ReadActivityRows(db, keys), count, page, size);
    }

    /// <summary>分页选好主键后只取列表的白名单字段，事件正文仍由连接详情接口单独读取。</summary>
    private static IReadOnlyList<RealtimeInteractionEvent> ReadActivityRows(HoneypotDbContext db, ActivityPageKey[] keys)
    {
        if (keys.Length == 0) return [];
        var ids = JsonSerializer.Serialize(keys.Select(row => row.EventId));
        var items = db.Database.SqlQuery<ActivityRow>($"""
            SELECT EventId, ConnectionId, Sequence, EventType, OccurredAtUtcTicks, SourceIp, DestinationPort, AdapterKey,
                coalesce(json_extract(EventJson,'$.SourcePort'),0) AS SourcePort,
                coalesce(json_extract(EventJson,'$.DestinationIp'),'') AS DestinationIp,
                coalesce(json_extract(EventJson,'$.ListenerId'),'') AS ListenerId,
                coalesce(json_extract(EventJson,'$.ServiceInstanceId'),'') AS ServiceInstanceId,
                coalesce(json_extract(EventJson,'$.Stage'),'') AS Stage,
                coalesce(json_extract(EventJson,'$.Outcome'),'') AS Outcome,
                CASE WHEN json_extract(EventJson,'$.CredentialArtifactId') IS NULL
                     THEN json_extract(EventJson,'$.PayloadSummary') END AS PayloadSummary,
                json_extract(EventJson,'$.Username') AS Username, json_extract(EventJson,'$.Domain') AS Domain,
                json_extract(EventJson,'$.Database') AS DatabaseName, json_extract(EventJson,'$.AuthenticationMethod') AS AuthenticationMethod,
                json_extract(EventJson,'$.AuthenticationFailureCode') AS AuthenticationFailureCode,
                json_extract(EventJson,'$.AuthenticationAttempt') AS AuthenticationAttempt,
                json_extract(EventJson,'$.MaterialType') AS MaterialType, json_extract(EventJson,'$.CredentialCaptureStatus') AS CredentialCaptureStatus,
                json_extract(EventJson,'$.CredentialCaptureError') AS CredentialCaptureError,
                json_extract(EventJson,'$.CredentialMaterialBytes') AS CredentialMaterialBytes,
                json_extract(EventJson,'$.CredentialArtifactId') AS CredentialArtifactId, coalesce(json_extract(EventJson,'$.RiskDelta'),0) AS RiskDelta,
                json_extract(EventJson,'$.CloseReason') AS CloseReason
            FROM interaction_events WHERE EventId IN (SELECT value FROM json_each({ids}))
            """).AsEnumerable().ToDictionary(row => row.EventId, StringComparer.OrdinalIgnoreCase);
        return keys.Select(key =>
        {
            var row = items[key.EventId];
            return new RealtimeInteractionEvent(row.EventId, row.ConnectionId, row.Sequence, row.EventType,
                new DateTimeOffset(row.OccurredAtUtcTicks, TimeSpan.Zero), row.SourceIp, row.SourcePort, row.DestinationIp,
                row.DestinationPort, row.ListenerId, row.ServiceInstanceId, row.AdapterKey, row.Stage, row.Outcome,
                row.PayloadSummary, row.Username, row.RiskDelta, row.CredentialArtifactId, !string.IsNullOrEmpty(row.CredentialArtifactId))
            {
                Domain = row.Domain, Database = row.DatabaseName, AuthenticationMethod = row.AuthenticationMethod,
                AuthenticationFailureCode = row.AuthenticationFailureCode, AuthenticationAttempt = row.AuthenticationAttempt,
                MaterialType = row.MaterialType, CredentialCaptureStatus = row.CredentialCaptureStatus,
                CredentialCaptureError = row.CredentialCaptureError, CredentialMaterialBytes = row.CredentialMaterialBytes,
                CloseReason = row.CloseReason is { } reason ? ((SessionCloseReason)reason).ToString() : null,
                EventCount = key.Observed, ConnectionCloseObserved = key.CloseObserved,
            };
        }).ToArray();
    }

    private sealed record ActivityRow(string EventId, string ConnectionId, long Sequence, string EventType, long OccurredAtUtcTicks,
        string SourceIp, int SourcePort, string DestinationIp, int DestinationPort, string ListenerId, string ServiceInstanceId,
        string AdapterKey, string Stage, string Outcome, string? PayloadSummary, string? Username, string? Domain, string? DatabaseName,
        string? AuthenticationMethod, string? AuthenticationFailureCode, int? AuthenticationAttempt, string? MaterialType,
        string? CredentialCaptureStatus, string? CredentialCaptureError, int? CredentialMaterialBytes, string? CredentialArtifactId, int RiskDelta, int? CloseReason);
}
