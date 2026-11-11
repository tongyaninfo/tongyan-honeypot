using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Honeypot.Api.Data.Migrations
{
    /// <inheritdoc />
    public partial class InitialCreate : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "service_instances",
                columns: table => new
                {
                    InstanceId = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false),
                    DisplayName = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                    AdapterKey = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    ProfileJson = table.Column<string>(type: "TEXT", nullable: false),
                    DesiredState = table.Column<string>(type: "TEXT", maxLength: 32, nullable: false),
                    AutoStart = table.Column<bool>(type: "INTEGER", nullable: false),
                    CurrentState = table.Column<string>(type: "TEXT", maxLength: 32, nullable: false),
                    LastError = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: true),
                    CreatedAtUtc = table.Column<DateTimeOffset>(type: "TEXT", nullable: false),
                    UpdatedAtUtc = table.Column<DateTimeOffset>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_service_instances", x => x.InstanceId);
                });

            migrationBuilder.CreateTable(
                name: "listener_bindings",
                columns: table => new
                {
                    ListenerId = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false),
                    InstanceId = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false),
                    BindAddress = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false),
                    Port = table.Column<int>(type: "INTEGER", nullable: false),
                    Transport = table.Column<string>(type: "TEXT", maxLength: 16, nullable: false),
                    Enabled = table.Column<bool>(type: "INTEGER", nullable: false),
                    MaxConnections = table.Column<int>(type: "INTEGER", nullable: false),
                    MaxConnectionsPerIp = table.Column<int>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_listener_bindings", x => x.ListenerId);
                    table.ForeignKey(
                        name: "FK_listener_bindings_service_instances_InstanceId",
                        column: x => x.InstanceId,
                        principalTable: "service_instances",
                        principalColumn: "InstanceId",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_listener_bindings_BindAddress_Port_Transport",
                table: "listener_bindings",
                columns: new[] { "BindAddress", "Port", "Transport" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_listener_bindings_InstanceId",
                table: "listener_bindings",
                column: "InstanceId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "listener_bindings");

            migrationBuilder.DropTable(
                name: "service_instances");
        }
    }
}
