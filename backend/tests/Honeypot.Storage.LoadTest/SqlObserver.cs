using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore.Diagnostics;

namespace Honeypot.Storage.LoadTest;

/// <summary>只记录错误码与 SQL 形状，避免输出事件数据、凭据和语句参数。</summary>
internal sealed class SqlObserver : IObserver<DiagnosticListener>, IObserver<KeyValuePair<string, object?>>, IStartupFilter, IDisposable
{
    private readonly ConcurrentBag<IDisposable> subscriptions = [];
    private readonly AsyncLocal<string?> route = new();
    private static readonly Regex FullJson = new("""(?:SELECT|,)\s*(?:(?:"\w+"|\w+)\.)?"?EventJson"?\s*(?:AS|,|\sFROM)""",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);
    public ConcurrentDictionary<string, int> SqliteErrors { get; } = new();
    public ConcurrentDictionary<string, int> EntireJsonQueries { get; } = new();
    public ConcurrentDictionary<string, int> ReadCommands { get; } = new();
    public SqlObserver() => subscriptions.Add(DiagnosticListener.AllListeners.Subscribe(this));
    public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
    {
        app.Use(async (context, tail) =>
        {
            route.Value = context.Request.Path.Value;
            try { await tail(); } finally { route.Value = null; }
        });
        next(app);
    };
    public void OnNext(DiagnosticListener listener)
    {
        if (listener.Name == "Microsoft.EntityFrameworkCore") subscriptions.Add(listener.Subscribe(this,
            (name, _, _) => name.EndsWith(".CommandExecuted", StringComparison.Ordinal) || name.EndsWith(".CommandError", StringComparison.Ordinal)));
    }
    public void OnNext(KeyValuePair<string, object?> entry)
    {
        if (entry.Value is CommandErrorEventData { Exception: SqliteException error })
            SqliteErrors.AddOrUpdate(error.SqliteErrorCode.ToString(), 1, (_, n) => n + 1);
        if (entry.Value is CommandExecutedEventData sql && route.Value is { } path &&
            (path == DashboardLoad.Overview || path == DashboardLoad.Map || path == "/api/v1/events"))
        {
            ReadCommands.AddOrUpdate(path, 1, (_, n) => n + 1);
            if (FullJson.IsMatch(sql.Command.CommandText))
                EntireJsonQueries.AddOrUpdate(path, 1, (_, n) => n + 1);
        }
    }
    public void OnError(Exception error) { }
    public void OnCompleted() { }
    public void Dispose() { foreach (var handle in subscriptions) handle.Dispose(); }
}
