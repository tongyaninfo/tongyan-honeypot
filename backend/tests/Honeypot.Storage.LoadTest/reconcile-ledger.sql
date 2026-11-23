-- 对已结束并正常关闭的隔离压测库做第二次核验。两张事件表各自计数，
-- 单边缺失不会因为内连接而消失。认证次数按每条连接上的顺序独立重建。
WITH details AS (
    SELECT EventId,ConnectionId,Sequence,EventType FROM interaction_events WHERE EventId GLOB 'live-*'
), facts AS (
    SELECT EventId,IsAuthenticationFailure,CredentialArtifactId FROM report_events WHERE EventId GLOB 'live-*'
), attempts AS (
    SELECT EventId,ConnectionId,EventJson,
           row_number() OVER (PARTITION BY ConnectionId ORDER BY Sequence) AS ordinal
    FROM interaction_events WHERE EventId GLOB 'live-*' AND EventType='AuthenticationAttempted'
), evidence AS (
    SELECT ArtifactId,EventId,ConnectionId FROM credential_evidence WHERE EventId GLOB 'live-*'
), traces AS (
    SELECT ConnectionId,ObservedCount,AuthenticationActivityCount
    FROM connection_summaries WHERE ConnectionId GLOB 'live-*'
)
SELECT
    (SELECT count(*) FROM traces) AS live_connections,
    (SELECT count(*) FROM details) AS live_steps,
    (SELECT count(*) FROM facts) AS live_facts,
    (SELECT count(*) FROM attempts) AS live_authentications,
    (SELECT count(*) FROM evidence) AS live_evidence,
    (SELECT count(*) FROM details LEFT JOIN facts USING(EventId) WHERE facts.EventId IS NULL) AS missing_facts,
    (SELECT count(*) FROM facts LEFT JOIN details USING(EventId) WHERE details.EventId IS NULL) AS missing_details,
    (SELECT count(*) FROM (
        SELECT ConnectionId FROM details GROUP BY ConnectionId
        HAVING min(Sequence)<>1 OR max(Sequence)<>count(*) OR count(DISTINCT Sequence)<>count(*)
    )) AS broken_sequences,
    (SELECT count(*) FROM attempts WHERE json_extract(EventJson,'$.AuthenticationAttempt') IS NOT ordinal
       OR json_extract(EventJson,'$.AuthenticationFailureCode') IS NOT 'denied'
       OR json_extract(EventJson,'$.CredentialCaptureStatus') IS NOT 'Captured') AS incorrect_authentication_metadata,
    (SELECT count(*) FROM facts f LEFT JOIN evidence e ON e.ArtifactId=f.CredentialArtifactId AND e.EventId=f.EventId
       WHERE f.IsAuthenticationFailure=1 AND e.ArtifactId IS NULL) AS authentication_without_evidence,
    (SELECT count(*) FROM evidence e LEFT JOIN attempts a ON a.EventId=e.EventId AND a.ConnectionId=e.ConnectionId
       WHERE a.EventId IS NULL) AS orphan_evidence,
    (SELECT count(*) FROM interaction_events WHERE EventId GLOB 'hs-*') AS historical_details,
    (SELECT count(*) FROM report_events WHERE EventId GLOB 'hs-*') AS historical_facts,
    (SELECT count(*) FROM connection_summaries WHERE ConnectionId GLOB 'hist-*') AS historical_connections,
    (SELECT count(*) FROM credential_evidence WHERE ConnectionId GLOB 'hist-*') AS historical_evidence;
