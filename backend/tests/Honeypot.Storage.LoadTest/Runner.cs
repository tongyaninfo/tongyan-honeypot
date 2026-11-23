using System.Collections.Concurrent;
using System.Diagnostics.Metrics;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;
using Honeypot.Api.Service;
using Honeypot.Api.Service.impl;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Honeypot.Storage.LoadTest;

internal static class Runner
{
    private static IEnumerable<DirectoryInfo> EnumerableFrom(string path)
    {
        for (var d = new DirectoryInfo(path); d is not null; d = d.Parent) yield return d;
    }

    public static async Task<int> Main(string[] args)
    {
        if (args is ["snapshot", var file, var output, var asOf, var count, .. var remaining] && remaining.Length <= 1)
        {
            var rounds = int.Parse(count, System.Globalization.CultureInfo.InvariantCulture);
            if (rounds is < 1 or > 100) throw new ArgumentOutOfRangeException(nameof(rounds));
            var snapshotClients = remaining.Length == 0 ? 1 : int.Parse(remaining[0], System.Globalization.CultureInfo.InvariantCulture);
            if (snapshotClients is < 1 or > 8) throw new ArgumentOutOfRangeException(nameof(snapshotClients));
            return await SnapshotBenchmark.RunAsync(file, output,
                DateTimeOffset.Parse(asOf, System.Globalization.CultureInfo.InvariantCulture), rounds, snapshotClients);
        }
        if (args is ["seed"] or ["seed-small"])
        {
            Console.WriteLine(await HistoricalFixture.CreateAsync(args[0] == "seed-small"));
            return 0;
        }
        if (args is not [("smoke" or "full"), var directory]) throw new ArgumentException("seed | seed-small | smoke <fixture> | full <fixture> | snapshot <closed-db> <result.json> <utc> <rounds> [clients]");
        directory = Path.GetFullPath(directory);
        if (!directory.StartsWith(Path.TrimEndingDirectorySeparator(Path.GetTempPath()) + Path.DirectorySeparatorChar, StringComparison.Ordinal)
            || !Path.GetFileName(directory).StartsWith("honeypot-storage-replay-", StringComparison.Ordinal)
            || new DirectoryInfo(directory).LinkTarget is not null || !File.Exists(Path.Combine(directory, "isolated-replay.json")))
            throw new ArgumentException("只能使用本工具创建的隔离夹具");
        // 独立测试进程读取这些值，应用配置加载期间也不会接触默认工作区数据库。
        Environment.SetEnvironmentVariable("Honeypot__DataDirectory", directory);
        Environment.SetEnvironmentVariable("Honeypot__CredentialEvidence__KeyDirectory", Path.Combine(directory, "credential-evidence-keys"));
        var project = EnumerableFrom(AppContext.BaseDirectory).Select(d => Path.Combine(d.FullName, "src", "Honeypot.Api")).First(Directory.Exists);
        Environment.SetEnvironmentVariable("ASPNETCORE_TEST_CONTENTROOT_HONEYPOT_API", project);
        using var meter = new MeterListener();
        var stages = new ConcurrentDictionary<string, Timings>();
        meter.InstrumentPublished = (instrument, listener) => { if (instrument.Meter.Name == "Honeypot.Storage") listener.EnableMeasurementEvents(instrument); };
        meter.SetMeasurementEventCallback<double>((instrument, value, _, _) => stages.GetOrAdd(instrument.Name, _ => new()).Record(value));
        meter.Start();
        using var sqlObserver = new SqlObserver();
        await using var factory = new WebApplicationFactory<global::Program>().WithWebHostBuilder(builder =>
        {
            builder.UseContentRoot(project);
            builder.ConfigureLogging(logging => logging.ClearProviders());
            builder.ConfigureServices(services => services.AddSingleton<IStartupFilter>(sqlObserver));
            builder.UseSetting("Honeypot:DataDirectory", directory);
        });
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions { BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false });
        var identity = factory.Services.GetRequiredService<IUserIdentityService>();
        string password = Convert.ToHexString(RandomNumberGenerator.GetBytes(20)) + "z!";
        var adminResult = await identity.InitializeFirstAdminAsync("localfixture", password);
        if (!adminResult.Succeeded) throw new InvalidDataException("夹具已被使用或隔离初始化失败");
        var login = await identity.LoginAsync("localfixture", password);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", login.Session!.AccessToken);
        var admin = login.Session.User;
        var full = args[0] == "full";
        var dashboard = new DashboardLoad(client);
        var replay = new LiveReplay(factory.Services);
        var health = factory.Services.GetRequiredService<ReportIngestionHealth>();
        var dbPath = Path.Combine(directory, "honeypot.db");
        using (var local = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = dbPath, Mode = SqliteOpenMode.ReadOnly }.ToString()))
        {
            local.Open();
            using var check = local.CreateCommand();
            check.CommandText = "SELECT count(*) FROM connection_summaries";
            var expected = JsonDocument.Parse(await File.ReadAllTextAsync(Path.Combine(directory, "isolated-replay.json"))).RootElement.GetProperty("connections").GetInt32();
            if (Convert.ToInt32(check.ExecuteScalar()) != expected || (full && expected != 130000)) throw new InvalidDataException("历史迁移对账失败");
        }
        Console.WriteLine($"READY {DateTimeOffset.Now:O} databaseMiB={new FileInfo(dbPath).Length / 1048576d:F1}");
        var retention = new RetentionLoad(dbPath);
        retention.Schedule(full ? 75 : 1);
        using var stop = new CancellationTokenSource();
        var clients = Enumerable.Range(0, 3).Select(_ => Task.Run(() => dashboard.RunDashboard(stop.Token))).Append(Task.Run(() => dashboard.RunReports(stop.Token))).ToArray();
        var results = new List<PhaseResult>();
        try
        {
            var first = await replay.RunAsync("sustained", 1235, full ? TimeSpan.FromHours(1) : TimeSpan.FromSeconds(10));
            Console.WriteLine(JsonSerializer.Serialize(first));
            results.Add(first);
            dashboard.Phase = "burst";
            var burst = await replay.RunAsync("burst", 2470, full ? TimeSpan.FromMinutes(15) : TimeSpan.FromSeconds(5));
            Console.WriteLine(JsonSerializer.Serialize(burst));
            results.Add(burst);
        }
        finally
        {
            stop.Cancel();
            await Task.WhenAll(clients);
        }
        var dashboardChecks = await DashboardVerification.ReadAsync(client, dbPath);
        var checkpoint = retention.Read();
        var audit = Reconciliation.Read(directory, replay.Sessions, factory.Services.GetRequiredService<ICredentialEvidenceAccessService>(), admin);
        var readQueriesVerified = new[] { DashboardLoad.Overview, DashboardLoad.Map, "/api/v1/events" }
            .All(sqlObserver.ReadCommands.ContainsKey) && sqlObserver.EntireJsonQueries.IsEmpty;
        var readLatencyPassed = results.All(phase => DashboardLoad.DashboardEndpoints.All(endpoint =>
            dashboard.ByPhase.TryGetValue(phase.Name + " " + endpoint, out var samples) && samples.P95 <= 1000));
        var ledgerMatched = audit.ExpectedConnections == audit.MatchedConnections &&
            audit.ExpectedAuthentications == audit.MatchedAuthentications &&
            audit is { MissingSteps: 0, UnsolicitedSteps: 0, UnexpectedConnections: 0, UnexpectedEvidence: 0, RiskCountMatches: true };
        var passed = ledgerMatched && replay.Passed && readLatencyPassed && readQueriesVerified &&
            dashboardChecks.All(check => check.Expected == check.Actual) &&
            (!full || checkpoint.Removed > 0) && checkpoint.Busy == 0 && checkpoint.WalFrames == checkpoint.CompletedFrames &&
            sqlObserver.SqliteErrors.IsEmpty && health.Errors.Count == 0 && health.RejectedEvents == 0 &&
            health.PersistenceFailures == 0 && health.EventQueueDepth == 0 && dashboard.Errors.IsEmpty;
        var result = new
        {
            passed,
            dashboardChecks,
            maintenance = new { checkpoint.Removed, checkpoint.Remaining, checkpoint.Busy, checkpoint.WalFrames, checkpoint.CompletedFrames },
            phases = results,
            audit,
            storage = new
            {
                health.PersistenceFailures,
                health.RejectedEvents,
                health.LockRetries,
                health.Errors,
                health.EventQueueDepth,
                health.RetentionAvailable,
                walBytes = new FileInfo(dbPath + "-wal").Length
            },
            sqlDiagnostics = new { sqlObserver.SqliteErrors, sqlObserver.EntireJsonQueries, sqlObserver.ReadCommands },
            stages = stages.ToDictionary(p => p.Key, p => p.Value.Summary()),
            ingestErrors = replay.Failures,
            endpointsByPhase = dashboard.ByPhase.ToDictionary(p => p.Key, p => p.Value.Summary()),
            endpointErrors = dashboard.Errors,
            endpoints = dashboard.Timings.ToDictionary(p => p.Key, p => p.Value.Summary())
        };
        var json = JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(Path.Combine(directory, "result.json"), json);
        Console.WriteLine(json);
        return passed ? 0 : 1;
    }
}
