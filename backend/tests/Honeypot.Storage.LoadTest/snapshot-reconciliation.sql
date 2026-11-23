-- 用 sqlite3 -readonly "file:<切换后固定快照>?immutable=1" < snapshot-reconciliation.sql 复算。
-- 首页正式第一轮的模拟时钟。输出聚合计数，不读取明细正文或证据材料。
.bail on
.mode list
PRAGMA query_only = ON;
BEGIN;
WITH
clock AS (
    SELECT '2026-11-22T12:52:34Z' AS as_of,
           unixepoch('2026-11-22T12:52:34Z') * 1000 AS end_ms
),
bounds AS (
    SELECT as_of, end_ms, end_ms - 30 * 86400000 AS retained_after_ms,
           end_ms - 86400000 AS start_ms,
           (end_ms - 86400000) * 10000 + 621355968000000000 AS start_ticks,
           end_ms * 10000 + 621355968000000000 AS end_ticks,
           unixepoch(as_of,'+8 hours','start of day','-8 hours') * 1000 AS midnight_ms
    FROM clock
),
-- 总览直接点数仍可读取的原始事件。接纳按连接去重，认证/异常按独立事件计数。
day_details AS (
    SELECT d.EventId, d.ConnectionId, d.EventType
    FROM bounds b CROSS JOIN interaction_events d
    WHERE d.OccurredAtUtcTicks BETWEEN b.start_ticks AND b.end_ticks
      AND d.ReceivedAtUnixMs > b.retained_after_ms
      AND (d.ShortRetentionUntilUnixMs IS NULL OR d.ShortRetentionUntilUnixMs > b.end_ms)
),
overview AS (
    SELECT COUNT(*) AS events,
           COUNT(DISTINCT CASE WHEN EventType='ConnectionAccepted' THEN ConnectionId END) AS accepted,
           COUNT(*) FILTER (WHERE EventType='AuthenticationAttempted') AS attempts,
           COUNT(*) FILTER (WHERE EventType='ProtocolViolation') AS violations,
           COUNT(*) FILTER (WHERE EventType='SessionClosed') AS closed
    FROM day_details
),
-- 独立按报告的认证结果分类，与 API 使用的 IsAuthenticationFailure 标志交叉验证。
day_facts AS (
    SELECT COUNT(*) AS facts,
           COUNT(*) FILTER (WHERE f.Outcome='') AS without_outcome,
           COUNT(*) FILTER (WHERE d.EventId IS NULL) AS without_detail,
           COUNT(*) FILTER (WHERE f.EventType='authenticationattempted' AND d.EventId IS NOT NULL AND
                             f.Outcome IN ('failure','rejected','invalid')) AS failures,
           COUNT(*) FILTER (WHERE f.EventType='authenticationattempted' AND d.EventId IS NOT NULL AND
                             f.Outcome IN ('failure','rejected','invalid') AND f.OccurredAtUnixMs>=b.midnight_ms) AS today_failures
    FROM bounds b CROSS JOIN report_events f
    LEFT JOIN day_details d ON d.EventId=f.EventId
    WHERE f.OccurredAtUnixMs BETWEEN b.start_ms AND b.end_ms
),
-- 威胁数以仍有效的来源档案为准。以原始明细中同时存在未到期来源独立校验可追溯性。
profiles AS (
    SELECT COUNT(*) AS active_profiles,
           COUNT(*) FILTER (WHERE EXISTS (
              SELECT 1 FROM interaction_events d WHERE d.SourceIp=p.SourceIp
                AND d.OccurredAtUtcTicks<=b.end_ticks AND d.ReceivedAtUnixMs>b.retained_after_ms
                AND (d.ShortRetentionUntilUnixMs IS NULL OR d.ShortRetentionUntilUnixMs>b.end_ms)
           )) AS traceable_profiles
    FROM bounds b CROSS JOIN threat_ip_profiles p
    WHERE p.ExpiresAtUnixMs>b.end_ms
),
-- 最近活动覆盖快照里尚能展示的全部连接，时间窗独立于总览的滚动 24h。
-- 仅用原始事件类型、序号、时间和标识复算优先级与代表事件，不使用摘要的代表键及计数。
steps AS (
    SELECT EventId, ConnectionId, EventType, Sequence, OccurredAtUtcTicks, ReceivedAtUnixMs, ShortRetentionUntilUnixMs,
           CASE WHEN EventType IN ('AuthenticationAttempted','AuthorizationDenied') THEN 4
                WHEN EventType IN ('StorageDegraded','CredentialCaptureFailed','AuthenticationEventWriteFailed') THEN 3
                WHEN EventType IN ('ProtocolViolation','HandshakeTimeout','AuthenticationRequired','CaptureTruncated',
                                   'ResourceLimitExceeded','RuleMatched') THEN 2
                WHEN EventType IN ('ConnectionAccepted','ConnectionRejected') THEN 1 ELSE 0 END AS priority
    FROM interaction_events
),
ranked AS (
    SELECT s.*, ROW_NUMBER() OVER (PARTITION BY ConnectionId ORDER BY
             priority DESC,
             CASE WHEN priority=1 THEN Sequence END ASC, Sequence DESC,
             CASE WHEN priority=1 THEN OccurredAtUtcTicks END ASC, OccurredAtUtcTicks DESC,
             EventId COLLATE BINARY ASC) AS position
    FROM steps s
),
activities AS (
    SELECT COUNT(*) AS activity_count, COUNT(DISTINCT ConnectionId) AS connections,
           COUNT(*) FILTER (WHERE EventType='AuthenticationAttempted') AS attempts,
           COUNT(*) FILTER (WHERE EventType='AuthorizationDenied') AS denials,
           COUNT(*) FILTER (WHERE priority<4) AS representatives
    FROM ranked r CROSS JOIN bounds b
    WHERE (priority=4 OR position=1) AND r.ReceivedAtUnixMs>b.retained_after_ms
      AND (r.ShortRetentionUntilUnixMs IS NULL OR r.ShortRetentionUntilUnixMs>b.end_ms)
),
retention AS (
    SELECT COUNT(*) AS all_steps, COUNT(*) FILTER (WHERE d.ReceivedAtUnixMs<=b.retained_after_ms) AS beyond_days,
           COUNT(d.ShortRetentionUntilUnixMs) AS with_short_deadline,
           COUNT(*) FILTER (WHERE d.ShortRetentionUntilUnixMs<=b.end_ms) AS short_expired,
           MIN(d.ShortRetentionUntilUnixMs - d.ReceivedAtUnixMs) AS min_short_ms,
           MAX(d.ShortRetentionUntilUnixMs - d.ReceivedAtUnixMs) AS max_short_ms
    FROM interaction_events d CROSS JOIN bounds b
)
SELECT json_object('asOfUtc',b.as_of,'timezone','Asia/Shanghai',
   'overview',json_object('eventCount',o.events,'reportOnlyEvents',f.without_outcome,
       'acceptedConnections',o.accepted,'authenticationAttempts',o.attempts,'authenticationFailures',f.failures,
       'todayAuthenticationFailures',f.today_failures,'protocolViolations',o.violations,'sessionClosed',o.closed,
       'threatIpCount',p.active_profiles,'traceableThreatIpCount',p.traceable_profiles),
   'recentActivity',json_object('authenticationAttempted',a.attempts,'authorizationDenied',a.denials,
       'ordinaryRepresentatives',a.representatives,'total',a.activity_count,'distinctConnections',a.connections),
   'retention',json_object('detailDays',30,'storedDetails',r.all_steps,'pastDetailDeadline',r.beyond_days,
       'shortDeadlinePresent',r.with_short_deadline,'pastShortDeadline',r.short_expired,
       'minShortDurationMs',r.min_short_ms,'maxShortDurationMs',r.max_short_ms),
   'reportFacts24h',json_object('physical',f.facts,'missingDetail',f.without_detail,'withoutOutcome',f.without_outcome))
FROM bounds b CROSS JOIN overview o CROSS JOIN day_facts f CROSS JOIN profiles p CROSS JOIN activities a CROSS JOIN retention r;
COMMIT;
