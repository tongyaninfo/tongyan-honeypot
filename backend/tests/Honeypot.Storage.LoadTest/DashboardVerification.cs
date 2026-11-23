using System.Globalization;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Data.Sqlite;

namespace Honeypot.Storage.LoadTest;

internal sealed record DashboardCheck(string Name, long Expected, long Actual);

internal static class DashboardVerification
{
    // 通过原始明细和报告事实独立核对，避免拿摘要表验证摘要表本身。
    public static async Task<List<DashboardCheck>> ReadAsync(HttpClient client, string path)
    {
        using var db = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = path, Mode = SqliteOpenMode.ReadOnly }.ToString());
        db.Open();
        async Task<JsonElement> Get(string route)
        {
            var result = await client.GetFromJsonAsync<JsonElement>(route);
            return result.GetProperty("data");
        }
        long Count(string sql, long from, long until)
        {
            using var command = db.CreateCommand();
            command.CommandText = sql;
            command.Parameters.AddWithValue("$from", from);
            command.Parameters.AddWithValue("$until", until);
            return Convert.ToInt64(command.ExecuteScalar());
        }
        const string acceptedSql = """
            SELECT count(distinct ConnectionId) FROM interaction_events
            WHERE EventType='ConnectionAccepted' AND OccurredAtUtcTicks BETWEEN $from AND $until
            """;
        const string authSql = """
            SELECT count(*) FROM interaction_events e JOIN report_events f ON e.EventId=f.EventId
            WHERE f.IsAuthenticationFailure=1 AND e.OccurredAtUtcTicks BETWEEN $from AND $until
            """;
        var overview = await Get(DashboardLoad.Overview);
        var now = overview.GetProperty("generatedAtUtc").GetDateTimeOffset();
        var midnight = new DateTimeOffset(now.ToOffset(TimeSpan.FromHours(8)).Date, TimeSpan.FromHours(8));
        var stamp = Uri.EscapeDataString(now.ToString("O", CultureInfo.InvariantCulture));
        var accepted = Count(acceptedSql, now.AddHours(-24).UtcTicks, now.UtcTicks);
        var auth = Count(authSql, midnight.UtcTicks, now.UtcTicks);
        var checks = new List<DashboardCheck>
        {
            new("24h accepted", accepted, overview.GetProperty("acceptedConnections").GetInt64()),
            new("today authentication failures", auth, overview.GetProperty("todayAuthenticationFailures").GetInt64())
        };
        // 事件接收器回放没有网络监听，因此运行时活动数应为零；另以回环 TCP 测试验证非零快照。
        checks.Add(new("runtime active connections", 0, overview.GetProperty("activeConnections").GetInt64()));
        foreach (var (scope, expected) in new[] { ("accepted", accepted), ("authenticationFailures", auth), ("active", 0L) })
        {
            var page = await Get($"/api/v1/metrics/overview/connections?scope={scope}&pageSize=3&asOfUtc={stamp}");
            checks.Add(new("drilldown " + scope, expected, page.GetProperty("total").GetInt64()));
        }
        var map = await Get(DashboardLoad.Map);
        var mapTime = map.GetProperty("sampledAtUtc").GetDateTimeOffset();
        var mapCount = Count(acceptedSql, mapTime.AddSeconds(-map.GetProperty("windowSeconds").GetInt32()).UtcTicks, mapTime.UtcTicks);
        checks.Add(new("map window", mapCount, map.GetProperty("coverage").GetProperty("observed").GetInt64()));
        var activity = await Get("/api/v1/events?view=activity&page=1&pageSize=8");
        VerifyRecentActivity(db, now, activity, checks);
        foreach (var point in overview.GetProperty("activityByHour").EnumerateArray())
        {
            var hour = point.GetProperty("key").GetDateTimeOffset();
            var end = Math.Min(hour.AddHours(1).ToUnixTimeMilliseconds(), now.ToUnixTimeMilliseconds());
            foreach (var (metric, predicate) in new[] { ("acceptedConnections", "EventType='connectionaccepted'"), ("authenticationFailures", "IsAuthenticationFailure=1") })
            {
                var expected = Count($"SELECT count(*) FROM report_events WHERE {predicate} AND OccurredAtUnixMs >= $from AND OccurredAtUnixMs < $until", hour.ToUnixTimeMilliseconds(), end);
                var value = point.GetProperty(metric);
                checks.Add(new($"{hour:MM-dd HH} {metric}", expected, value.ValueKind == JsonValueKind.Null ? 0 : value.GetInt64()));
            }
        }
        return checks;
    }

    // 以脱敏明细独立重建业务活动，确保首页加速后仍能逐次显示认证并正确选择其他连接的代表记录。
    private static void VerifyRecentActivity(SqliteConnection db, DateTimeOffset now, JsonElement page, List<DashboardCheck> checks)
    {
        using var query = db.CreateCommand();
        query.CommandText = """
            WITH ranked AS (
                SELECT EventId, OccurredAtUtcTicks, Sequence, ActivityPriority,
                    row_number() OVER (PARTITION BY ConnectionId ORDER BY ActivityPriority DESC,
                        CASE WHEN ActivityPriority=1 THEN Sequence END ASC, Sequence DESC,
                        CASE WHEN ActivityPriority=1 THEN OccurredAtUtcTicks END ASC, OccurredAtUtcTicks DESC, EventId COLLATE BINARY) AS position
                FROM interaction_events WHERE ReceivedAtUnixMs>$cutoff AND (ShortRetentionUntilUnixMs IS NULL OR ShortRetentionUntilUnixMs>$now)
            ), activities AS (
                SELECT EventId,OccurredAtUtcTicks,Sequence FROM ranked WHERE ActivityPriority=4 OR position=1
            )
            SELECT EventId,count(*) OVER () FROM activities
            ORDER BY OccurredAtUtcTicks DESC,Sequence DESC,EventId COLLATE BINARY LIMIT 8
            """;
        query.Parameters.AddWithValue("$cutoff", now.AddDays(-30).ToUnixTimeMilliseconds());
        query.Parameters.AddWithValue("$now", now.ToUnixTimeMilliseconds());
        using var reader = query.ExecuteReader();
        var expectedIds = new List<string>();
        long expectedTotal = 0;
        while (reader.Read())
        {
            expectedIds.Add(reader.GetString(0));
            expectedTotal = reader.GetInt64(1);
        }
        var actualIds = page.GetProperty("items").EnumerateArray().Select(item => item.GetProperty("eventId").GetString());
        checks.Add(new("recent activity total", expectedTotal, page.GetProperty("total").GetInt64()));
        checks.Add(new("recent activity ordered event IDs", 1, expectedIds.SequenceEqual(actualIds) ? 1 : 0));
    }
}
