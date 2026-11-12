using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Honeypot.Api.Data.Migrations
{
    /// <inheritdoc />
    public partial class McpManagement : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "mcp_api_keys",
                columns: table => new
                {
                    Id = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false),
                    Prefix = table.Column<string>(type: "TEXT", maxLength: 24, nullable: false),
                    SecretDigest = table.Column<byte[]>(type: "BLOB", maxLength: 32, nullable: false),
                    Name = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    Mode = table.Column<string>(type: "TEXT", maxLength: 16, nullable: false),
                    PermissionsJson = table.Column<string>(type: "TEXT", nullable: false),
                    InstanceGrantsJson = table.Column<string>(type: "TEXT", nullable: false),
                    CreatedBy = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false),
                    CreatedUnixMs = table.Column<long>(type: "INTEGER", nullable: false),
                    ExpiresUnixMs = table.Column<long>(type: "INTEGER", nullable: true),
                    RevokedUnixMs = table.Column<long>(type: "INTEGER", nullable: true),
                    LastUsedUnixMs = table.Column<long>(type: "INTEGER", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_mcp_api_keys", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "mcp_call_audits",
                columns: table => new
                {
                    Id = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false),
                    OccurredUnixMs = table.Column<long>(type: "INTEGER", nullable: false),
                    KeyId = table.Column<string>(type: "TEXT", maxLength: 128, nullable: true),
                    KeyName = table.Column<string>(type: "TEXT", maxLength: 100, nullable: true),
                    KeyPrefix = table.Column<string>(type: "TEXT", maxLength: 24, nullable: true),
                    Tool = table.Column<string>(type: "TEXT", maxLength: 128, nullable: true),
                    McpMethod = table.Column<string>(type: "TEXT", maxLength: 128, nullable: true),
                    SourceIp = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                    HttpMethod = table.Column<string>(type: "TEXT", maxLength: 16, nullable: false),
                    HttpStatus = table.Column<int>(type: "INTEGER", nullable: true),
                    Result = table.Column<string>(type: "TEXT", maxLength: 24, nullable: false),
                    DurationMs = table.Column<long>(type: "INTEGER", nullable: true),
                    DetailsJson = table.Column<string>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_mcp_call_audits", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "mcp_settings",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false),
                    Enabled = table.Column<bool>(type: "INTEGER", nullable: false),
                    AuditRetentionDays = table.Column<int>(type: "INTEGER", nullable: false),
                    UpdatedUnixMs = table.Column<long>(type: "INTEGER", nullable: true),
                    UpdatedBy = table.Column<string>(type: "TEXT", maxLength: 128, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_mcp_settings", x => x.Id);
                    table.CheckConstraint("CK_mcp_settings_retention", "AuditRetentionDays BETWEEN 1 AND 365");
                    table.CheckConstraint("CK_mcp_settings_singleton", "Id = 1");
                });

            migrationBuilder.InsertData(
                table: "mcp_settings",
                columns: new[] { "Id", "AuditRetentionDays", "Enabled", "UpdatedBy", "UpdatedUnixMs" },
                values: new object[] { 1, 30, false, null, null });

            migrationBuilder.CreateIndex(
                name: "IX_mcp_api_keys_CreatedUnixMs_Id",
                table: "mcp_api_keys",
                columns: new[] { "CreatedUnixMs", "Id" });

            migrationBuilder.CreateIndex(
                name: "IX_mcp_api_keys_Prefix",
                table: "mcp_api_keys",
                column: "Prefix",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_mcp_call_audits_KeyId_OccurredUnixMs",
                table: "mcp_call_audits",
                columns: new[] { "KeyId", "OccurredUnixMs" });

            migrationBuilder.CreateIndex(
                name: "IX_mcp_call_audits_OccurredUnixMs_Id",
                table: "mcp_call_audits",
                columns: new[] { "OccurredUnixMs", "Id" });

            migrationBuilder.CreateIndex(
                name: "IX_mcp_call_audits_Result_OccurredUnixMs",
                table: "mcp_call_audits",
                columns: new[] { "Result", "OccurredUnixMs" });

            migrationBuilder.CreateIndex(
                name: "IX_mcp_call_audits_SourceIp_OccurredUnixMs",
                table: "mcp_call_audits",
                columns: new[] { "SourceIp", "OccurredUnixMs" });

            migrationBuilder.CreateIndex(
                name: "IX_mcp_call_audits_Tool_OccurredUnixMs",
                table: "mcp_call_audits",
                columns: new[] { "Tool", "OccurredUnixMs" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "mcp_api_keys");

            migrationBuilder.DropTable(
                name: "mcp_call_audits");

            migrationBuilder.DropTable(
                name: "mcp_settings");
        }
    }
}
