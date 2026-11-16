using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Honeypot.Api.Data.Migrations
{
    /// <inheritdoc />
    public partial class BusinessDataPersistence : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "credential_evidence",
                columns: table => new
                {
                    ArtifactId = table.Column<string>(type: "TEXT", maxLength: 37, nullable: false, collation: "NOCASE"),
                    ConnectionId = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false),
                    EventId = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false, collation: "NOCASE"),
                    SourceIp = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    AdapterKey = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    MaterialType = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    CapturedAtUtcTicks = table.Column<long>(type: "INTEGER", nullable: false),
                    RetentionUntilUtcTicks = table.Column<long>(type: "INTEGER", nullable: false),
                    KeyId = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    ContentBytes = table.Column<int>(type: "INTEGER", nullable: false),
                    Nonce = table.Column<byte[]>(type: "BLOB", maxLength: 12, nullable: false),
                    Tag = table.Column<byte[]>(type: "BLOB", maxLength: 16, nullable: false),
                    Ciphertext = table.Column<byte[]>(type: "BLOB", nullable: false),
                    PasswordBookFingerprint = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                    PasswordBookUsername = table.Column<string>(type: "TEXT", maxLength: 128, nullable: true),
                    PasswordBookOccurredAtUtcTicks = table.Column<long>(type: "INTEGER", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_credential_evidence", x => x.ArtifactId);
                });

            migrationBuilder.CreateTable(
                name: "credential_evidence_access_audits",
                columns: table => new
                {
                    AuditId = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false),
                    ArtifactId = table.Column<string>(type: "TEXT", maxLength: 37, nullable: false),
                    UserId = table.Column<string>(type: "TEXT", maxLength: 128, nullable: true),
                    OccurredAtUtcTicks = table.Column<long>(type: "INTEGER", nullable: false),
                    Outcome = table.Column<string>(type: "TEXT", maxLength: 32, nullable: false),
                    Operation = table.Column<string>(type: "TEXT", maxLength: 16, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_credential_evidence_access_audits", x => x.AuditId);
                });

            migrationBuilder.CreateTable(
                name: "interaction_events",
                columns: table => new
                {
                    EventId = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false, collation: "NOCASE"),
                    ConnectionId = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false, collation: "NOCASE"),
                    Sequence = table.Column<long>(type: "INTEGER", nullable: false),
                    OccurredAtUtcTicks = table.Column<long>(type: "INTEGER", nullable: false),
                    ReceivedAtUnixMs = table.Column<long>(type: "INTEGER", nullable: false),
                    SourceIp = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false, collation: "NOCASE"),
                    AdapterKey = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false, collation: "NOCASE"),
                    EventType = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false, collation: "NOCASE"),
                    DestinationPort = table.Column<int>(type: "INTEGER", nullable: false),
                    ActivityPriority = table.Column<int>(type: "INTEGER", nullable: false),
                    EventJson = table.Column<string>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_interaction_events", x => x.EventId);
                });

            migrationBuilder.CreateTable(
                name: "management_operation_audits",
                columns: table => new
                {
                    Id = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false),
                    OccurredAtUnixMs = table.Column<long>(type: "INTEGER", nullable: false),
                    Operation = table.Column<string>(type: "TEXT", maxLength: 48, nullable: false),
                    ActorUserId = table.Column<string>(type: "TEXT", maxLength: 128, nullable: true),
                    ResourceId = table.Column<string>(type: "TEXT", maxLength: 128, nullable: true),
                    HttpStatus = table.Column<int>(type: "INTEGER", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_management_operation_audits", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "threat_ip_profiles",
                columns: table => new
                {
                    SourceIp = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false, collation: "NOCASE"),
                    ThreatId = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false),
                    FirstSeenUtcTicks = table.Column<long>(type: "INTEGER", nullable: false),
                    LastSeenUtcTicks = table.Column<long>(type: "INTEGER", nullable: false),
                    ExpiresAtUnixMs = table.Column<long>(type: "INTEGER", nullable: false),
                    CurrentScore = table.Column<int>(type: "INTEGER", nullable: false),
                    MaxScore = table.Column<int>(type: "INTEGER", nullable: false),
                    ScoreVersion = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    Status = table.Column<string>(type: "TEXT", maxLength: 32, nullable: false, collation: "NOCASE"),
                    AttemptCount = table.Column<long>(type: "INTEGER", nullable: false),
                    SessionCount = table.Column<long>(type: "INTEGER", nullable: false),
                    ActiveSessionCount = table.Column<long>(type: "INTEGER", nullable: false),
                    AuthenticationAttemptCount = table.Column<long>(type: "INTEGER", nullable: false),
                    ProtocolViolationCount = table.Column<long>(type: "INTEGER", nullable: false),
                    ServicesJson = table.Column<string>(type: "TEXT", nullable: false),
                    PortsJson = table.Column<string>(type: "TEXT", nullable: false),
                    LastEventId = table.Column<string>(type: "TEXT", maxLength: 128, nullable: true),
                    LastReason = table.Column<string>(type: "TEXT", maxLength: 256, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_threat_ip_profiles", x => x.SourceIp);
                });

            migrationBuilder.CreateIndex(
                name: "IX_credential_evidence_CapturedAtUtcTicks_ArtifactId",
                table: "credential_evidence",
                columns: new[] { "CapturedAtUtcTicks", "ArtifactId" });

            migrationBuilder.CreateIndex(
                name: "IX_credential_evidence_EventId",
                table: "credential_evidence",
                column: "EventId",
                unique: true,
                filter: "\"PasswordBookOccurredAtUtcTicks\" IS NOT NULL");

            migrationBuilder.CreateIndex(
                name: "IX_credential_evidence_KeyId",
                table: "credential_evidence",
                column: "KeyId");

            migrationBuilder.CreateIndex(
                name: "IX_credential_evidence_PasswordBookFingerprint_PasswordBookOccurredAtUtcTicks_ArtifactId",
                table: "credential_evidence",
                columns: new[] { "PasswordBookFingerprint", "PasswordBookOccurredAtUtcTicks", "ArtifactId" },
                filter: "\"PasswordBookOccurredAtUtcTicks\" IS NOT NULL");

            migrationBuilder.CreateIndex(
                name: "IX_credential_evidence_RetentionUntilUtcTicks_ContentBytes",
                table: "credential_evidence",
                columns: new[] { "RetentionUntilUtcTicks", "ContentBytes" });

            migrationBuilder.CreateIndex(
                name: "IX_credential_evidence_access_audits_OccurredAtUtcTicks_AuditId",
                table: "credential_evidence_access_audits",
                columns: new[] { "OccurredAtUtcTicks", "AuditId" });

            migrationBuilder.CreateIndex(
                name: "IX_interaction_events_AdapterKey_OccurredAtUtcTicks",
                table: "interaction_events",
                columns: new[] { "AdapterKey", "OccurredAtUtcTicks" });

            migrationBuilder.CreateIndex(
                name: "IX_interaction_events_ConnectionId_Sequence_OccurredAtUtcTicks",
                table: "interaction_events",
                columns: new[] { "ConnectionId", "Sequence", "OccurredAtUtcTicks" });

            migrationBuilder.CreateIndex(
                name: "IX_interaction_events_DestinationPort_OccurredAtUtcTicks",
                table: "interaction_events",
                columns: new[] { "DestinationPort", "OccurredAtUtcTicks" });

            migrationBuilder.CreateIndex(
                name: "IX_interaction_events_EventType_OccurredAtUtcTicks",
                table: "interaction_events",
                columns: new[] { "EventType", "OccurredAtUtcTicks" });

            migrationBuilder.CreateIndex(
                name: "IX_interaction_events_OccurredAtUtcTicks_Sequence",
                table: "interaction_events",
                columns: new[] { "OccurredAtUtcTicks", "Sequence" });

            migrationBuilder.CreateIndex(
                name: "IX_interaction_events_ReceivedAtUnixMs",
                table: "interaction_events",
                column: "ReceivedAtUnixMs");

            migrationBuilder.CreateIndex(
                name: "IX_interaction_events_SourceIp_OccurredAtUtcTicks",
                table: "interaction_events",
                columns: new[] { "SourceIp", "OccurredAtUtcTicks" });

            migrationBuilder.CreateIndex(
                name: "IX_management_operation_audits_OccurredAtUnixMs_Id",
                table: "management_operation_audits",
                columns: new[] { "OccurredAtUnixMs", "Id" });

            migrationBuilder.CreateIndex(
                name: "IX_threat_ip_profiles_CurrentScore_AuthenticationAttemptCount_LastSeenUtcTicks_SourceIp",
                table: "threat_ip_profiles",
                columns: new[] { "CurrentScore", "AuthenticationAttemptCount", "LastSeenUtcTicks", "SourceIp" },
                descending: new[] { true, true, true, false });

            migrationBuilder.CreateIndex(
                name: "IX_threat_ip_profiles_CurrentScore_LastSeenUtcTicks_SourceIp",
                table: "threat_ip_profiles",
                columns: new[] { "CurrentScore", "LastSeenUtcTicks", "SourceIp" },
                descending: new[] { true, true, false });

            migrationBuilder.CreateIndex(
                name: "IX_threat_ip_profiles_ExpiresAtUnixMs",
                table: "threat_ip_profiles",
                column: "ExpiresAtUnixMs");

            migrationBuilder.CreateIndex(
                name: "IX_threat_ip_profiles_LastSeenUtcTicks_SourceIp",
                table: "threat_ip_profiles",
                columns: new[] { "LastSeenUtcTicks", "SourceIp" },
                descending: new[] { true, false });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "credential_evidence");

            migrationBuilder.DropTable(
                name: "credential_evidence_access_audits");

            migrationBuilder.DropTable(
                name: "interaction_events");

            migrationBuilder.DropTable(
                name: "management_operation_audits");

            migrationBuilder.DropTable(
                name: "threat_ip_profiles");
        }
    }
}
