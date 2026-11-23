using Microsoft.Data.Sqlite;

namespace Honeypot.Storage.LoadTest;

/// <summary>预置即将分批到期的运行采样，确保持续压测中清理器实际删除记录。</summary>
internal sealed class RetentionLoad(string path)
{
    private readonly long first = DateTimeOffset.UtcNow.AddDays(-90).AddSeconds(15).ToUnixTimeMilliseconds();
    private const int SamplesPerMinute = 64;
    private int total;
    private SqliteConnection Open()
    {
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = path }.ToString());
        connection.Open();
        return connection;
    }
    public void Schedule(int minutes)
    {
        total = minutes * SamplesPerMinute;
        using var db = Open();
        using var cmd = db.CreateCommand();
        cmd.CommandText = """
            WITH RECURSIVE ids(n) AS (VALUES(0) UNION ALL SELECT n+1 FROM ids WHERE n+1<$total)
            INSERT INTO report_runtime_samples(CapturedAtUnixMs,CoverageStartAtUnixMs,ActiveConnections,
                ConfiguredListeners,RunningListeners,FailedListeners,PersistenceFailures,ProcessMemoryBytes)
            SELECT $start+(n/$per)*60000+(n%$per),$start+(n/$per)*60000+(n%$per),0,0,0,0,0,0 FROM ids
            """;
        cmd.Parameters.AddWithValue("$start", first);
        cmd.Parameters.AddWithValue("$per", SamplesPerMinute);
        cmd.Parameters.AddWithValue("$total", total);
        cmd.ExecuteNonQuery();
    }
    public (int Removed, int Remaining, int Busy, int WalFrames, int CompletedFrames) Read()
    {
        using var db = Open();
        using var cmd = db.CreateCommand();
        cmd.CommandText = "SELECT count(*) FROM report_runtime_samples WHERE CapturedAtUnixMs BETWEEN $start AND $end";
        cmd.Parameters.AddWithValue("$start", first);
        cmd.Parameters.AddWithValue("$end", first + ((total - 1) / SamplesPerMinute) * 60000 + SamplesPerMinute);
        var remaining = Convert.ToInt32(cmd.ExecuteScalar());
        cmd.CommandText = "PRAGMA wal_checkpoint(PASSIVE)";
        using var reader = cmd.ExecuteReader();
        if (!reader.Read()) throw new InvalidOperationException("缺少 WAL 状态");
        return (total - remaining, remaining, reader.GetInt32(0), reader.GetInt32(1), reader.GetInt32(2));
    }
}
