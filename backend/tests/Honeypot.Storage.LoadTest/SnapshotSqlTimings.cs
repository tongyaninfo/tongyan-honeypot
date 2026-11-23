using System.Collections.Concurrent;
using System.Data.Common;
using System.Diagnostics;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore.Diagnostics;

namespace Honeypot.Storage.LoadTest;

/// <summary>按请求记录从发出 SQL 到关闭游标的时间，包含读行和物化。结果中只保留 SQL 模板和执行计划。</summary>
internal sealed class SnapshotSqlTimings : IStartupFilter, IObserver<DiagnosticListener>,
    IObserver<KeyValuePair<string, object?>>, IDisposable
{
    private readonly ConcurrentBag<IDisposable> subscriptions = [];
    private readonly AsyncLocal<(string Path, int Client)?> route = new();
    private readonly ConcurrentDictionary<Guid, (long Start, int Round, int Client, Shape Query)> pending = new();
    private readonly ConcurrentDictionary<(string Route, string Sql), Shape> shapes = new();
    private sealed record Shape(string Route, string Sql, (string Name, object? Value)[] Parameters)
    {
        public ConcurrentBag<(int Round, int Client, double Ms)> Elapsed { get; } = [];
    }

    public int Round { get; set; } = -1;

    public SnapshotSqlTimings() => subscriptions.Add(DiagnosticListener.AllListeners.Subscribe(this));

    public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
    {
        app.Use(async (context, continuation) =>
        {
            var path = context.Request.Path.Value;
            if (path == "/api/v1/metrics/overview" || path == "/api/v1/events" && context.Request.Query["view"] == "activity")
            {
                int.TryParse(context.Request.Headers["X-Snapshot-Client"], out var client);
                route.Value = (path, client);
            }
            try { await continuation(); }
            finally { route.Value = null; }
        });
        next(app);
    };

    public void OnNext(DiagnosticListener listener)
    {
        if (listener.Name == "Microsoft.EntityFrameworkCore") subscriptions.Add(listener.Subscribe(this));
    }

    public void OnNext(KeyValuePair<string, object?> item)
    {
        if (item.Value is DataReaderDisposingEventData reader)
        {
            Complete(reader.CommandId);
            return;
        }
        if (item.Value is not CommandEventData data) return;
        if (item.Key.EndsWith(".CommandExecuting", StringComparison.Ordinal) && Round >= 0 && route.Value is { } request)
        {
            var shape = shapes.GetOrAdd((request.Path, data.Command.CommandText), key => new Shape(key.Route, key.Sql,
                data.Command.Parameters.Cast<DbParameter>().Select(p => (p.ParameterName, p.Value)).ToArray()));
            pending[data.CommandId] = (Stopwatch.GetTimestamp(), Round, request.Client, shape);
        }
        else if (item.Key.EndsWith(".CommandExecuted", StringComparison.Ordinal) && data.ExecuteMethod != DbCommandMethod.ExecuteReader
            || item.Key.EndsWith(".CommandError", StringComparison.Ordinal))
        {
            Complete(data.CommandId);
        }
    }

    private void Complete(Guid id)
    {
        if (pending.TryRemove(id, out var entry))
            entry.Query.Elapsed.Add((entry.Round, entry.Client, Stopwatch.GetElapsedTime(entry.Start).TotalMilliseconds));
    }

    public object Results(string connectionString)
    {
        if (!pending.IsEmpty || shapes.Keys.Select(key => key.Route).Distinct().Count() != 2)
            throw new InvalidOperationException("两个目标接口必须有完整的 SQL 计时");
        using var connection = new SqliteConnection(connectionString);
        connection.Open();
        return shapes.Values.OrderBy(s => s.Route).ThenBy(s => s.Sql).Select(shape =>
        {
            using var cmd = connection.CreateCommand();
            cmd.CommandText = "EXPLAIN QUERY PLAN " + shape.Sql;
            foreach (var (name, value) in shape.Parameters) cmd.Parameters.AddWithValue(name, value ?? DBNull.Value);
            using var reader = cmd.ExecuteReader();
            var plan = new List<string>();
            while (reader.Read()) plan.Add(reader.GetString(3));
            var byRound = shape.Elapsed.GroupBy(sample => (sample.Round, sample.Client)).OrderBy(group => group.Key)
                .Select(group => Math.Round(group.Sum(sample => sample.Ms), 2)).ToArray();
            return new { shape.Route, shape.Sql, plan, calls = shape.Elapsed.Count, byRound, perRequest = SnapshotBenchmark.Stats(byRound) };
        }).ToArray();
    }

    public void OnCompleted() { }
    public void OnError(Exception error) => throw error;
    public void Dispose()
    {
        foreach (var subscription in subscriptions) subscription.Dispose();
    }
}
