using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Honeypot.Api.Data.Migrations
{
    /// <inheritdoc />
    public partial class ReportNotifications : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "report_events",
                columns: table => new
                {
                    EventId = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false, collation: "NOCASE"),
                    OccurredAtUnixMs = table.Column<long>(type: "INTEGER", nullable: false),
                    EventType = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    SourceIp = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    AdapterKey = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    DestinationPort = table.Column<int>(type: "INTEGER", nullable: false),
                    Username = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false),
                    AuthenticationMethod = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    IsAuthenticationFailure = table.Column<bool>(type: "INTEGER", nullable: false),
                    RiskSignal = table.Column<string>(type: "TEXT", maxLength: 16, nullable: false),
                    EvidenceKind = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    CredentialArtifactId = table.Column<string>(type: "TEXT", maxLength: 128, nullable: true),
                    CaptureTruncated = table.Column<bool>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_report_events", x => x.EventId);
                });

            migrationBuilder.CreateTable(
                name: "report_runtime_samples",
                columns: table => new
                {
                    CapturedAtUnixMs = table.Column<long>(type: "INTEGER", nullable: false),
                    CoverageStartAtUnixMs = table.Column<long>(type: "INTEGER", nullable: false),
                    ProcessCpuPercent = table.Column<double>(type: "REAL", nullable: true),
                    ProcessMemoryBytes = table.Column<long>(type: "INTEGER", nullable: false),
                    DataDiskFreeBytes = table.Column<long>(type: "INTEGER", nullable: true),
                    ActiveConnections = table.Column<long>(type: "INTEGER", nullable: false),
                    ConfiguredListeners = table.Column<int>(type: "INTEGER", nullable: false),
                    RunningListeners = table.Column<int>(type: "INTEGER", nullable: false),
                    FailedListeners = table.Column<int>(type: "INTEGER", nullable: false),
                    PersistenceFailures = table.Column<long>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_report_runtime_samples", x => x.CapturedAtUnixMs);
                });

            migrationBuilder.CreateTable(
                name: "report_snapshots",
                columns: table => new
                {
                    Id = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false),
                    PeriodKind = table.Column<string>(type: "TEXT", nullable: false),
                    TaskKey = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                    PeriodStartUnixMs = table.Column<long>(type: "INTEGER", nullable: false),
                    PeriodEndUnixMs = table.Column<long>(type: "INTEGER", nullable: false),
                    CreatedUnixMs = table.Column<long>(type: "INTEGER", nullable: false),
                    ReportJson = table.Column<string>(type: "TEXT", nullable: false),
                    TemplateVersion = table.Column<string>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_report_snapshots", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "report_source_first_seen",
                columns: table => new
                {
                    SourceIp = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    FirstSeenAtUnixMs = table.Column<long>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_report_source_first_seen", x => x.SourceIp);
                });

            migrationBuilder.CreateTable(
                name: "email_deliveries",
                columns: table => new
                {
                    Id = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false),
                    ReportSnapshotId = table.Column<string>(type: "TEXT", nullable: true),
                    Kind = table.Column<string>(type: "TEXT", nullable: false),
                    Recipient = table.Column<string>(type: "TEXT", maxLength: 320, nullable: false),
                    RecipientKey = table.Column<string>(type: "TEXT", maxLength: 320, nullable: false),
                    DeduplicationKey = table.Column<string>(type: "TEXT", maxLength: 512, nullable: false),
                    MessageId = table.Column<string>(type: "TEXT", nullable: false),
                    Subject = table.Column<string>(type: "TEXT", nullable: false),
                    HtmlBody = table.Column<string>(type: "TEXT", nullable: false),
                    TextBody = table.Column<string>(type: "TEXT", nullable: false),
                    Status = table.Column<string>(type: "TEXT", nullable: false),
                    AttemptCount = table.Column<int>(type: "INTEGER", nullable: false),
                    AutomaticAttemptCount = table.Column<int>(type: "INTEGER", nullable: false),
                    CreatedUnixMs = table.Column<long>(type: "INTEGER", nullable: false),
                    UpdatedUnixMs = table.Column<long>(type: "INTEGER", nullable: false),
                    NextAttemptUnixMs = table.Column<long>(type: "INTEGER", nullable: true),
                    AcceptedUnixMs = table.Column<long>(type: "INTEGER", nullable: true),
                    LeaseExpiresUnixMs = table.Column<long>(type: "INTEGER", nullable: true),
                    LastErrorCode = table.Column<string>(type: "TEXT", nullable: true),
                    LastErrorMessage = table.Column<string>(type: "TEXT", nullable: true),
                    RequestedBy = table.Column<string>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_email_deliveries", x => x.Id);
                    table.ForeignKey(
                        name: "FK_email_deliveries_report_snapshots_ReportSnapshotId",
                        column: x => x.ReportSnapshotId,
                        principalTable: "report_snapshots",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "email_delivery_attempts",
                columns: table => new
                {
                    Id = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false),
                    DeliveryId = table.Column<string>(type: "TEXT", nullable: false),
                    Number = table.Column<int>(type: "INTEGER", nullable: false),
                    StartedUnixMs = table.Column<long>(type: "INTEGER", nullable: false),
                    CompletedUnixMs = table.Column<long>(type: "INTEGER", nullable: true),
                    Status = table.Column<string>(type: "TEXT", nullable: false),
                    ErrorCode = table.Column<string>(type: "TEXT", nullable: true),
                    ErrorMessage = table.Column<string>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_email_delivery_attempts", x => x.Id);
                    table.ForeignKey(
                        name: "FK_email_delivery_attempts_email_deliveries_DeliveryId",
                        column: x => x.DeliveryId,
                        principalTable: "email_deliveries",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateIndex(
                name: "IX_email_deliveries_CreatedUnixMs",
                table: "email_deliveries",
                column: "CreatedUnixMs");

            migrationBuilder.CreateIndex(
                name: "IX_email_deliveries_DeduplicationKey",
                table: "email_deliveries",
                column: "DeduplicationKey",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_email_deliveries_ReportSnapshotId",
                table: "email_deliveries",
                column: "ReportSnapshotId");

            migrationBuilder.CreateIndex(
                name: "IX_email_deliveries_Status_NextAttemptUnixMs",
                table: "email_deliveries",
                columns: new[] { "Status", "NextAttemptUnixMs" });

            migrationBuilder.CreateIndex(
                name: "IX_email_delivery_attempts_DeliveryId_Number",
                table: "email_delivery_attempts",
                columns: new[] { "DeliveryId", "Number" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_email_delivery_attempts_StartedUnixMs",
                table: "email_delivery_attempts",
                column: "StartedUnixMs");

            migrationBuilder.CreateIndex(
                name: "IX_report_events_EventType_OccurredAtUnixMs",
                table: "report_events",
                columns: new[] { "EventType", "OccurredAtUnixMs" });

            migrationBuilder.CreateIndex(
                name: "IX_report_events_OccurredAtUnixMs",
                table: "report_events",
                column: "OccurredAtUnixMs");

            migrationBuilder.CreateIndex(
                name: "IX_report_events_SourceIp_OccurredAtUnixMs",
                table: "report_events",
                columns: new[] { "SourceIp", "OccurredAtUnixMs" });

            migrationBuilder.CreateIndex(
                name: "IX_report_runtime_samples_CoverageStartAtUnixMs",
                table: "report_runtime_samples",
                column: "CoverageStartAtUnixMs");

            migrationBuilder.CreateIndex(
                name: "IX_report_snapshots_PeriodKind_CreatedUnixMs",
                table: "report_snapshots",
                columns: new[] { "PeriodKind", "CreatedUnixMs" });

            migrationBuilder.CreateIndex(
                name: "IX_report_snapshots_TaskKey",
                table: "report_snapshots",
                column: "TaskKey",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_report_source_first_seen_FirstSeenAtUnixMs",
                table: "report_source_first_seen",
                column: "FirstSeenAtUnixMs");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "email_delivery_attempts");

            migrationBuilder.DropTable(
                name: "report_events");

            migrationBuilder.DropTable(
                name: "report_runtime_samples");

            migrationBuilder.DropTable(
                name: "report_source_first_seen");

            migrationBuilder.DropTable(
                name: "email_deliveries");

            migrationBuilder.DropTable(
                name: "report_snapshots");
        }
    }
}
