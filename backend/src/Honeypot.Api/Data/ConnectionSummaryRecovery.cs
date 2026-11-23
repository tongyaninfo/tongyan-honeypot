using System.Text.Json;
using Honeypot.Api.Data.Models;
using Microsoft.EntityFrameworkCore;

namespace Honeypot.Api.Data;

/// <summary>第一批程序回退时仍可向同库追加旧格式明细。再次升级按事件主键分批补充，保留从前已到期的步骤计数。</summary>
internal static class ConnectionSummaryRecovery
{
    internal static async Task RunAsync(HoneypotDbContext db, CancellationToken cancellationToken)
    {
        var cursor = "";
        while (true)
        {
            // 旧程序没有 Outcome 列映射，SQLite 将其填为默认空串。仅报告、没有真实详情的记录继续保持未知。
            var pending = await db.Database.SqlQuery<LegacyStep>($"""
                SELECT r.EventId,e.ReceivedAtUnixMs,e.EventJson
                FROM report_events r JOIN interaction_events e ON e.EventId=r.EventId
                WHERE r.Outcome='' AND r.EventId>{cursor}
                ORDER BY r.EventId LIMIT 512
                """).ToListAsync(cancellationToken);
            if (pending.Count == 0) return;
            var rows = pending.Select(step => (Event: InteractionEventEntity.Read(step.EventJson), step.ReceivedAtUnixMs)).ToArray();
            var connectionIds = rows.Select(row => row.Event.ConnectionId).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
            var keys = JsonSerializer.Serialize(pending.Select(row => row.EventId));
            await using var tx = await db.Database.BeginTransactionAsync(cancellationToken);
            // 标记与摘要一起提交。若有并发启动，只有实际取得该批次的执行者才能更新计数。
            var marked = await db.Database.ExecuteSqlInterpolatedAsync($"""
                UPDATE report_events AS r SET Outcome=coalesce(nullif(lower(json_extract(e.EventJson,'$.Outcome')),''),'unknown')
                FROM interaction_events AS e WHERE r.EventId=e.EventId AND r.Outcome=''
                    AND r.EventId IN (SELECT value FROM json_each({keys}))
                """, cancellationToken);
            if (marked != pending.Count)
            {
                await tx.RollbackAsync(cancellationToken);
                continue;
            }
            var summaries = db.Set<ConnectionSummaryEntity>();
            var existing = await summaries.Where(row => connectionIds.Contains(row.ConnectionId))
                .ToDictionaryAsync(row => row.ConnectionId, StringComparer.OrdinalIgnoreCase, cancellationToken);
            foreach (var row in rows)
            {
                if (!existing.TryGetValue(row.Event.ConnectionId, out var summary))
                {
                    summary = new ConnectionSummaryEntity { ConnectionId = row.Event.ConnectionId };
                    existing.Add(row.Event.ConnectionId, summary);
                    summaries.Add(summary);
                }
                summary.Observe(row.Event, DateTimeOffset.FromUnixTimeMilliseconds(row.ReceivedAtUnixMs));
            }
            await db.SaveChangesAsync(cancellationToken);
            await tx.CommitAsync(cancellationToken);
            db.ChangeTracker.Clear();
            cursor = pending[^1].EventId;
        }
    }

    private sealed record LegacyStep(string EventId, long ReceivedAtUnixMs, string EventJson);
}
