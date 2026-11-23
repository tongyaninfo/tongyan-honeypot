using System.Diagnostics;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Honeypot.Api.Data;
using Honeypot.Api.Service;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Honeypot.Storage.LoadTest;

/// <summary>挂载已关库的只读快照，以真实 HTTP 路由复测首页。无采集、迁移、定位、通知或定时清理任务。</summary>
internal static class SnapshotBenchmark
{
    private sealed class BenchmarkClock(DateTimeOffset instant) : TimeProvider
    {
        public DateTimeOffset Current { get; set; } = instant;
        public override DateTimeOffset GetUtcNow() => Current;
    }

    private sealed record Sample(int Round, int Client, string Route, double Milliseconds, string? Digest, Dictionary<string, string>? Fields, Dictionary<string, long>? Counts);
    private static readonly string[] Routes =
    [
        "/api/v1/metrics/overview", "/api/v1/metrics/overview/connection-map", "/api/v1/events?view=activity&page=1&pageSize=8",
        "/api/v1/threats?sort=risk&pageSize=8", "/api/v1/credential-evidence?pageSize=1"
    ];

    public static async Task<int> RunAsync(string database, string output, DateTimeOffset instant, int rounds, int clients)
    {
        // immutable 只对离线、无待合并 WAL 的输入使用。数据库和密钥均不进入结果文件。
        database = Path.GetFullPath(database);
        if (File.Exists(database + "-wal") && new FileInfo(database + "-wal").Length > 0)
            throw new InvalidOperationException("快照带未合并的 WAL");
        if (!File.Exists(database)) throw new FileNotFoundException("找不到离线快照", database);
        // 独占新结果文件，避免把快照本身或先前的验收结果作为输出覆盖。
        await using var resultFile = new FileStream(output, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        var local = Directory.CreateTempSubdirectory("honeypot-snapshot-query-").FullName;
        var root = Path.Combine(local, "api");
        Directory.CreateDirectory(root);
        Environment.SetEnvironmentVariable("Honeypot__DataDirectory", local);
        Environment.SetEnvironmentVariable("ASPNETCORE_TEST_CONTENTROOT_HONEYPOT_API", root);
        var uri = new Uri(database).AbsoluteUri + "?immutable=1";
        var cs = new SqliteConnectionStringBuilder { DataSource = uri, Mode = SqliteOpenMode.ReadOnly, Cache = SqliteCacheMode.Private, ForeignKeys = true }.ToString();
        var clock = new BenchmarkClock(instant);
        using var sql = new SnapshotSqlTimings();
        await using var factory = new WebApplicationFactory<global::Program>().WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment("Production");
            builder.UseContentRoot(root);
            builder.ConfigureLogging(logging => logging.ClearProviders());
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<IHostedService>();
                services.RemoveAll<TimeProvider>();
                services.AddSingleton<TimeProvider>(clock);
                services.RemoveAll<IDbContextFactory<HoneypotDbContext>>();
                services.RemoveAll<IDbContextOptionsConfiguration<HoneypotDbContext>>();
                services.RemoveAll<DbContextOptions<HoneypotDbContext>>();
                services.AddDbContextFactory<HoneypotDbContext>(options => options.UseSqlite(cs), ServiceLifetime.Singleton);
                services.AddSingleton<IStartupFilter>(sql);
            });
        });
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions { BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false });
        var identity = factory.Services.GetRequiredService<IUserIdentityService>();
        var pwd = Convert.ToHexString(RandomNumberGenerator.GetBytes(24)) + "z!";
        if (!(await identity.InitializeFirstAdminAsync("snapshot-admin", pwd)).Succeeded) throw new InvalidOperationException("隔离管理员初始化失败");
        var login = await identity.LoginAsync("snapshot-admin", pwd);
        if (login.Session is null) throw new InvalidOperationException("隔离管理员登录失败");
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", login.Session.AccessToken);

        var samples = new List<Sample>();
        async Task<Sample> Fetch(string route, int round, int clientNumber)
        {
            var start = Stopwatch.GetTimestamp();
            using var request = new HttpRequestMessage(HttpMethod.Get, route);
            request.Headers.Add("X-Snapshot-Client", clientNumber.ToString(System.Globalization.CultureInfo.InvariantCulture));
            using var response = await client.SendAsync(request);
            var body = await response.Content.ReadAsByteArrayAsync();
            var elapsed = Stopwatch.GetElapsedTime(start).TotalMilliseconds;
            if (!response.IsSuccessStatusCode) throw new InvalidOperationException($"{route}: HTTP {(int)response.StatusCode}");
            var envelope = JsonNode.Parse(body)!.AsObject();
            if (!(bool)envelope["success"]!) throw new InvalidOperationException($"{route}: 业务响应失败");
            string? digest = null;
            Dictionary<string, string>? fields = null;
            Dictionary<string, long>? counts = null;
            if (route == Routes[0] || route.StartsWith("/api/v1/events", StringComparison.Ordinal))
            {
                var data = envelope["data"]!.AsObject();
                if (route == Routes[0]) data.Remove("host"); // 地址、主机名与开机时间是运行环境信息。
                string Hash(JsonNode? node) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(node?.ToJsonString() ?? "null")));
                digest = Hash(data);
                fields = data.ToDictionary(pair => pair.Key, pair => Hash(pair.Value));
                counts = data.Where(pair => pair.Value is JsonValue n && n.TryGetValue<long>(out _))
                    .ToDictionary(pair => pair.Key, pair => (long)pair.Value!);
            }
            return new(round, clientNumber, route, Math.Round(elapsed, 2), digest, fields, counts);
        }
        for (var i = -1; i < rounds; i++)
        {
            // 各版本使用相同的一系列统计截止点；每轮推进 5 秒，避免同一时点刷新复用内存采样。
            clock.Current = instant.AddSeconds((i + 1) * 5);
            sql.Round = i;
            var round = await Task.WhenAll(Enumerable.Range(0, clients).SelectMany(clientNumber =>
                Routes.Select(route => Task.Run(() => Fetch(route, i, clientNumber)))));
            samples.AddRange(round);
            Console.WriteLine($"round {i} overview={round[0].Milliseconds:F1} activity={round[2].Milliseconds:F1}");
        }
        var payload = new
        {
            fromUtc = instant, rounds, clients, cold = samples.Where(x => x.Round < 0), samples = samples.Where(x => x.Round >= 0),
            endpoints = samples.Where(x => x.Round >= 0).GroupBy(x => x.Route).ToDictionary(g => g.Key, g => Stats(g.Select(x => x.Milliseconds))),
            commands = sql.Results(cs)
        };
        await JsonSerializer.SerializeAsync(resultFile, payload, new JsonSerializerOptions { WriteIndented = true });
        return 0;
    }

    internal static object Stats(IEnumerable<double> values)
    {
        var a = values.Order().ToArray();
        double P(double p) => Math.Round(a[(int)Math.Ceiling(a.Length * p) - 1], 2);
        return new { count = a.Length, p50 = P(.5), p95 = P(.95), max = P(1) };
    }
}
