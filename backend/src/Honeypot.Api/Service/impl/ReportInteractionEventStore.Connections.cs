using Honeypot.Api.Data;
using Honeypot.Api.Data.Models;
using Honeypot.Protocol.Abstractions.Models;
using Honeypot.Api.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.Data.Sqlite;

namespace Honeypot.Api.Service.impl;

public sealed partial class ReportInteractionEventStore
{
    private static async Task UpdateConnectionSummaryAsync(HoneypotDbContext db, InteractionEvent item,
        DateTimeOffset receivedAt, CancellationToken cancellationToken)
    {
        var summaries = db.Set<ConnectionSummaryEntity>();
        var row = await summaries.FindAsync([item.ConnectionId], cancellationToken);
        if (row is null)
        {
            row = new ConnectionSummaryEntity { ConnectionId = item.ConnectionId };
            summaries.Add(row);
        }
        row.Observe(item, receivedAt);
    }

    public ConnectionTraceSummary? ReadConnectionSummary(string connectionId)
    {
        using var db = OpenReadContext();
        db.Database.OpenConnection();
        using var read = ((SqliteConnection)db.Database.GetDbConnection()).BeginTransaction(deferred: true);
        using var contextTransaction = db.Database.UseTransaction(read);
        var now = _time.GetUtcNow();
        var cutoff = now.AddDays(-_options.DetailRetentionDays).ToUnixTimeMilliseconds();
        var row = db.Set<ConnectionSummaryEntity>().AsNoTracking().SingleOrDefault(item =>
            item.ConnectionId == connectionId && item.LastReceivedAtUnixMs > cutoff);
        if (row is null) return null;
        return new(row.ConnectionId, row.SourceIp, row.SourcePort, row.DestinationIp, row.DestinationPort,
            row.AdapterKey, row.ListenerId, row.ServiceInstanceId, row.AdmissionOutcome, row.AdmissionReason,
            row.AdmittedAtUtcTicks is { } accepted ? new DateTimeOffset(accepted, TimeSpan.Zero) : null, row.LastStage,
            row.ClosedAtUtcTicks is { } closed ? new DateTimeOffset(closed, TimeSpan.Zero) : null, row.CloseReason?.ToString(),
            row.ObservedCount, Active(db, now).Count(item => item.ConnectionId == connectionId));
    }
}
