using Honeypot.Api.Common;
using Honeypot.Api.Models;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace Honeypot.Api.Service.impl;

public sealed partial class ReportInteractionEventStore
{
    internal QueryPageResult<OverviewConnectionRow> ReadOverviewPage(string scope, string? adapter, string? metric,
        DateTimeOffset now, int? page, int? pageSize)
    {
        var start = scope switch
        {
            "adapterActivity" => OverviewActivityProjection.HourWindow(now).Start,
            "authenticationFailures" => new DateTimeOffset(now.ToOffset(TimeSpan.FromHours(8)).Date, TimeSpan.FromHours(8)),
            "threatConnections" => now.AddDays(-_options.DetailRetentionDays),
            _ => now.AddHours(-24),
        };
        var accepted = scope is "accepted" or "threatConnections" || metric == "acceptedConnections";
        var distinct = scope == "threatConnections" || metric == "sourceIpCount";
        var columns = accepted ? """
            SELECT c.AdmissionEventId AS Id,c.ConnectionId,c.AdmittedAtUtcTicks AS Ticks,c.SourceIp,c.SourcePort,c.AdapterKey,c.DestinationPort,
                NULL AS Username,NULL AS CredentialArtifactId,NULL AS MaterialType,NULL AS EventType,NULL AS ProtocolViolationSummary
            FROM connection_summaries AS c WHERE c.AdmissionOutcome='accepted'
              AND c.AdmittedAtUtcTicks BETWEEN @fromTicks AND @toTicks AND c.LastReceivedAtUnixMs>@retained
            """ : """
            SELECT e.EventId AS Id,e.ConnectionId,e.OccurredAtUtcTicks AS Ticks,e.SourceIp,
                coalesce(json_extract(e.EventJson,'$.SourcePort'),0) AS SourcePort,e.AdapterKey,e.DestinationPort,
                CASE WHEN @showAuth THEN json_extract(e.EventJson,'$.Username') END AS Username,
                CASE WHEN @showAuth THEN f.CredentialArtifactId END AS CredentialArtifactId,
                CASE WHEN @showAuth THEN json_extract(e.EventJson,'$.MaterialType') END AS MaterialType,
                CASE WHEN @showType THEN e.EventType END AS EventType,
                CASE WHEN @showViolation THEN json_extract(e.EventJson,'$.PayloadSummary') END AS ProtocolViolationSummary
            FROM report_events AS f JOIN interaction_events AS e ON e.EventId=f.EventId
            WHERE f.OccurredAtUnixMs BETWEEN @fromMs AND @toMs AND e.OccurredAtUtcTicks BETWEEN @fromTicks AND @toTicks AND e.ReceivedAtUnixMs>@retained
            """;
        if (scope == "threatConnections")
        {
            // 只接入即被限流的来源也有真实连接；旧来源没有接纳步骤时使用实际观测到的代表步骤。
            columns = """
                SELECT coalesce(c.AdmissionEventId,c.RepresentativeId) AS Id,c.ConnectionId,
                    coalesce(c.AdmittedAtUtcTicks,c.RepresentativeUtcTicks) AS Ticks,c.SourceIp,c.SourcePort,c.AdapterKey,c.DestinationPort,
                    NULL AS Username,NULL AS CredentialArtifactId,NULL AS MaterialType,
                    CASE WHEN c.AdmissionOutcome='rejected' THEN 'ConnectionRejected' END AS EventType,NULL AS ProtocolViolationSummary
                FROM connection_summaries c JOIN threat_ip_profiles t ON t.SourceIp=c.SourceIp
                WHERE t.ExpiresAtUnixMs>@toMs AND c.LastReceivedAtUnixMs>@retained AND coalesce(c.AdmittedAtUtcTicks,c.RepresentativeUtcTicks)<=@toTicks
                """;
        }
        if (scope == "adapterActivity") columns += accepted ? " AND c.AdapterKey=@adapter" : " AND e.AdapterKey=@adapter";
        if (!accepted)
            columns += metric switch
            {
                "protocolViolations" => " AND f.EventType='protocolviolation'",
                "sourceIpCount" => " AND (f.EventType='protocolviolation' OR f.IsAuthenticationFailure) AND e.SourceIp NOT IN ('','unknown')",
                _ => " AND f.IsAuthenticationFailure",
            };
        if (metric == "sourceIpCount")
        {
            // 接纳来源取自逐连接摘要；其余来自可回看认证失败和协议异常，和协议卡使用相同集合。
            columns += """
                 UNION ALL SELECT c.AdmissionEventId,c.ConnectionId,c.AdmittedAtUtcTicks,c.SourceIp,c.SourcePort,c.AdapterKey,
                    c.DestinationPort,NULL,NULL,NULL,'ConnectionAccepted',NULL
                 FROM connection_summaries c WHERE c.AdmissionOutcome='accepted' AND c.AdapterKey=@adapter
                    AND c.SourceIp NOT IN ('','unknown') AND c.AdmittedAtUtcTicks BETWEEN @fromTicks AND @toTicks AND c.LastReceivedAtUnixMs>@retained
                """;
        }
        const string fields = "Id,ConnectionId,Ticks,SourceIp,SourcePort,AdapterKey,DestinationPort,Username,CredentialArtifactId,MaterialType,EventType,ProtocolViolationSummary";
        var sql = distinct ? $"SELECT {fields} FROM (SELECT b.*,row_number() OVER(PARTITION BY SourceIp ORDER BY Ticks DESC,Id) AS rn FROM ({columns}) b) WHERE rn=1" : columns;
        using var db = OpenReadContext();
        db.Database.OpenConnection();
        using var read = ((SqliteConnection)db.Database.GetDbConnection()).BeginTransaction(deferred:true);
        using var contextTransaction = db.Database.UseTransaction(read);
        // SQL 分支仅由上层验证后的枚举选择。所有业务筛选值单独绑定，统计与分页共用快照。
        var query = db.Database.SqlQueryRaw<DrillRow>(sql,
            new SqliteParameter("@fromMs", start.ToUnixTimeMilliseconds()), new SqliteParameter("@toMs", now.ToUnixTimeMilliseconds()),
            new SqliteParameter("@fromTicks", start.UtcTicks), new SqliteParameter("@toTicks", now.UtcTicks),
            new SqliteParameter("@retained", _time.GetUtcNow().AddDays(-_options.DetailRetentionDays).ToUnixTimeMilliseconds()),
            new SqliteParameter("@adapter", adapter ?? ""), new SqliteParameter("@showAuth", scope == "authenticationFailures" || metric == "authenticationFailures"),
            new SqliteParameter("@showType", metric == "sourceIpCount"), new SqliteParameter("@showViolation", metric == "protocolViolations"));
        var (number, size, offset) = QueryPage.Bounds(page, pageSize);
        var total = query.Count();
        var items = offset < total ? query.OrderByDescending(row => row.Ticks).ThenBy(row => row.Id).Skip((int)offset).Take(size)
            .AsEnumerable().Select(row => new OverviewConnectionRow(row.Id, row.ConnectionId,
                new DateTimeOffset(row.Ticks, TimeSpan.Zero), row.SourceIp, row.SourcePort, row.AdapterKey, row.DestinationPort)
            { Username = row.Username, CredentialArtifactId = row.CredentialArtifactId, MaterialType = row.MaterialType,
                EventType = row.EventType, ProtocolViolationSummary = row.ProtocolViolationSummary }).ToArray() : [];
        return new(items, total, number, size);
    }

    private sealed record DrillRow(string Id, string ConnectionId, long Ticks, string SourceIp, int SourcePort,
        string AdapterKey, int DestinationPort, string? Username, string? CredentialArtifactId, string? MaterialType,
        string? EventType, string? ProtocolViolationSummary);
}
