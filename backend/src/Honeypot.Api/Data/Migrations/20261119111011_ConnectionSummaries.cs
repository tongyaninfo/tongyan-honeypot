using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Honeypot.Api.Data.Migrations
{
    /// <inheritdoc />
    public partial class ConnectionSummaries : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "Outcome",
                table: "report_events",
                type: "TEXT",
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<long>(
                name: "ShortRetentionUntilUnixMs",
                table: "interaction_events",
                type: "INTEGER",
                nullable: true);

            migrationBuilder.CreateTable(
                name: "connection_summaries",
                columns: table => new
                {
                    ConnectionId = table.Column<string>(type: "TEXT", nullable: false, collation: "NOCASE"),
                    SourceIp = table.Column<string>(type: "TEXT", nullable: false, collation: "NOCASE"),
                    SourcePort = table.Column<int>(type: "INTEGER", nullable: false),
                    DestinationIp = table.Column<string>(type: "TEXT", nullable: false),
                    DestinationPort = table.Column<int>(type: "INTEGER", nullable: false),
                    ListenerId = table.Column<string>(type: "TEXT", nullable: false),
                    ServiceInstanceId = table.Column<string>(type: "TEXT", nullable: false),
                    AdapterKey = table.Column<string>(type: "TEXT", nullable: false, collation: "NOCASE"),
                    AdmissionEventId = table.Column<string>(type: "TEXT", nullable: true),
                    AdmissionOutcome = table.Column<string>(type: "TEXT", nullable: true),
                    AdmissionReason = table.Column<string>(type: "TEXT", nullable: true),
                    AdmittedAtUtcTicks = table.Column<long>(type: "INTEGER", nullable: true),
                    ClosedAtUtcTicks = table.Column<long>(type: "INTEGER", nullable: true),
                    CloseReason = table.Column<int>(type: "INTEGER", nullable: true),
                    LastReceivedAtUnixMs = table.Column<long>(type: "INTEGER", nullable: false),
                    LastSequence = table.Column<long>(type: "INTEGER", nullable: false),
                    LastOccurredAtUtcTicks = table.Column<long>(type: "INTEGER", nullable: false),
                    LastStage = table.Column<string>(type: "TEXT", nullable: false),
                    ObservedCount = table.Column<int>(type: "INTEGER", nullable: false),
                    AuthenticationActivityCount = table.Column<int>(type: "INTEGER", nullable: false),
                    RepresentativeId = table.Column<string>(type: "TEXT", nullable: false),
                    RepresentativePriority = table.Column<int>(type: "INTEGER", nullable: false),
                    RepresentativeSequence = table.Column<long>(type: "INTEGER", nullable: false),
                    RepresentativeUtcTicks = table.Column<long>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_connection_summaries", x => x.ConnectionId);
                });

            // 回填只读取真实脱敏明细。旧版仅有报告事实时没有连接编号，不能据此补造连接。
            // 排序阶段只传递索引字段，避免对整批事件 JSON 反复复制、排序。
            migrationBuilder.Sql("""
                WITH ranked AS (
                    SELECT ConnectionId, EventId, ReceivedAtUnixMs, ActivityPriority,
                        ROW_NUMBER() OVER (PARTITION BY ConnectionId ORDER BY
                            (EventType IN ('ConnectionAccepted','ConnectionRejected')) DESC,
                            OccurredAtUtcTicks, Sequence, EventId) AS admission_rank,
                        ROW_NUMBER() OVER (PARTITION BY ConnectionId ORDER BY
                            (EventType='SessionClosed') DESC, OccurredAtUtcTicks DESC, Sequence DESC, EventId) AS close_rank,
                        ROW_NUMBER() OVER (PARTITION BY ConnectionId ORDER BY (EventType<>'SessionClosed') DESC, Sequence DESC, OccurredAtUtcTicks DESC, EventId) AS last_rank,
                        ROW_NUMBER() OVER (PARTITION BY ConnectionId ORDER BY ActivityPriority DESC,
                            CASE WHEN ActivityPriority=1 THEN Sequence ELSE -Sequence END,
                            CASE WHEN ActivityPriority=1 THEN OccurredAtUtcTicks ELSE -OccurredAtUtcTicks END, EventId) AS repr_rank
                    FROM interaction_events
                ), summary AS (
                    SELECT ConnectionId, COUNT(*) AS n, SUM(ActivityPriority=4) AS auth,
                           MAX(ReceivedAtUnixMs) AS received,
                           MAX(CASE WHEN admission_rank=1 THEN EventId END) AS first_id,
                           MAX(CASE WHEN close_rank=1 THEN EventId END) AS close_id,
                           MAX(CASE WHEN last_rank=1 THEN EventId END) AS last_id,
                           MAX(CASE WHEN repr_rank=1 THEN EventId END) AS repr_id
                    FROM ranked GROUP BY ConnectionId
                )
                INSERT INTO connection_summaries
                    (ConnectionId,SourceIp,SourcePort,DestinationIp,DestinationPort,ListenerId,ServiceInstanceId,AdapterKey,
                     AdmissionEventId,AdmissionOutcome,AdmissionReason,AdmittedAtUtcTicks,ClosedAtUtcTicks,CloseReason,
                     LastReceivedAtUnixMs,LastSequence,LastOccurredAtUtcTicks,LastStage,ObservedCount,AuthenticationActivityCount,
                     RepresentativeId,RepresentativePriority,RepresentativeSequence,RepresentativeUtcTicks)
                SELECT s.ConnectionId,f.SourceIp,coalesce(json_extract(f.EventJson,'$.SourcePort'),0),
                     coalesce(json_extract(f.EventJson,'$.DestinationIp'),''),f.DestinationPort,
                     coalesce(json_extract(f.EventJson,'$.ListenerId'),''),coalesce(json_extract(f.EventJson,'$.ServiceInstanceId'),''),f.AdapterKey,
                     CASE WHEN f.EventType IN ('ConnectionAccepted','ConnectionRejected') THEN f.EventId END,
                     CASE f.EventType WHEN 'ConnectionAccepted' THEN 'accepted' WHEN 'ConnectionRejected' THEN 'rejected' END,
                     CASE WHEN f.EventType='ConnectionRejected' THEN json_extract(f.EventJson,'$.PayloadSummary') END,
                     CASE WHEN f.EventType IN ('ConnectionAccepted','ConnectionRejected') THEN f.OccurredAtUtcTicks END,
                     CASE WHEN c.EventType='SessionClosed' THEN c.OccurredAtUtcTicks END,
                     CASE WHEN c.EventType='SessionClosed' THEN json_extract(c.EventJson,'$.CloseReason') END,
                     s.received,CASE WHEN l.EventType='SessionClosed' THEN 0 ELSE l.Sequence END,
                     CASE WHEN l.EventType='SessionClosed' THEN 0 ELSE l.OccurredAtUtcTicks END,
                     CASE WHEN l.EventType='SessionClosed' THEN '' ELSE coalesce(json_extract(l.EventJson,'$.Stage'),'') END,s.n,s.auth,
                     r.EventId,r.ActivityPriority,r.Sequence,r.OccurredAtUtcTicks
                FROM summary s
                JOIN interaction_events f ON f.EventId=s.first_id JOIN interaction_events c ON c.EventId=s.close_id
                JOIN interaction_events l ON l.EventId=s.last_id JOIN interaction_events r ON r.EventId=s.repr_id;
                UPDATE report_events AS r SET Outcome=coalesce(nullif(lower(json_extract(e.EventJson,'$.Outcome')),''),'unknown')
                FROM interaction_events AS e WHERE r.EventId=e.EventId;
                """);

            migrationBuilder.CreateIndex(
                name: "IX_interaction_events_ShortRetentionUntilUnixMs",
                table: "interaction_events",
                column: "ShortRetentionUntilUnixMs",
                filter: "\"ShortRetentionUntilUnixMs\" IS NOT NULL");

            migrationBuilder.CreateIndex(
                name: "IX_connection_summaries_AdmissionOutcome_AdmittedAtUtcTicks",
                table: "connection_summaries",
                columns: new[] { "AdmissionOutcome", "AdmittedAtUtcTicks" });

            migrationBuilder.CreateIndex(
                name: "IX_connection_summaries_LastReceivedAtUnixMs",
                table: "connection_summaries",
                column: "LastReceivedAtUnixMs");

            migrationBuilder.CreateIndex(
                name: "IX_connection_summaries_SourceIp_AdmittedAtUtcTicks",
                table: "connection_summaries",
                columns: new[] { "SourceIp", "AdmittedAtUtcTicks" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "connection_summaries");

            migrationBuilder.DropIndex(
                name: "IX_interaction_events_ShortRetentionUntilUnixMs",
                table: "interaction_events");

            migrationBuilder.DropColumn(
                name: "Outcome",
                table: "report_events");

            migrationBuilder.DropColumn(
                name: "ShortRetentionUntilUnixMs",
                table: "interaction_events");
        }
    }
}
