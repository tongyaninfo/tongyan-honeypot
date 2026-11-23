using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net.Http.Json;
using System.Text.Json;

namespace Honeypot.Storage.LoadTest;

/// <summary>使用 TestServer 实际中间件与端点，HTTP 不离开当前压测进程。</summary>
internal sealed class DashboardLoad(HttpClient client)
{
    public volatile string Phase = "sustained";
    public ConcurrentDictionary<string, Timings> ByPhase { get; } = new();
    public ConcurrentDictionary<string, Timings> Timings { get; } = new();
    public ConcurrentDictionary<string, int> Errors { get; } = new();
    internal const string Overview = "/api/v1/metrics/overview", Map = "/api/v1/metrics/overview/connection-map";
    internal static readonly string[] DashboardEndpoints =
    [
        Overview, Map, "/api/v1/events?view=activity&page=1&pageSize=8",
        "/api/v1/threats?sort=risk&pageSize=8", "/api/v1/credential-evidence?pageSize=1"
    ];
    private async Task<JsonElement?> Request(string path, HttpContent? content = null)
    {
        var phase = Phase;
        var started = Stopwatch.GetTimestamp();
        try
        {
            using var message = new HttpRequestMessage(content is null ? HttpMethod.Get : HttpMethod.Post, path) { Content = content };
            using var response = await client.SendAsync(message);
            response.EnsureSuccessStatusCode();
            using var body = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
            if (!body.RootElement.GetProperty("success").GetBoolean()) throw new InvalidDataException("API response failed");
            return body.RootElement.GetProperty("data").Clone();
        }
        catch (Exception e)
        {
            Errors.AddOrUpdate(path + " " + e.GetType().Name, 1, (_, n) => n + 1);
            return null;
        }
        finally
        {
            Timings.GetOrAdd(path, _ => new()).Add(started);
            ByPhase.GetOrAdd(phase + " " + path, _ => new()).Add(started);
        }
    }

    internal async Task RunDashboard(CancellationToken stopping)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(5));
        try
        {
            do
            {
                await Task.WhenAll(DashboardEndpoints.Select(endpoint => Request(endpoint)));
            } while (await timer.WaitForNextTickAsync(stopping));
        }
        catch (OperationCanceledException) when (stopping.IsCancellationRequested) { }
    }
    internal async Task RunReports(CancellationToken stopping)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromMinutes(1));
        try
        {
            do
            {
                await Task.WhenAll(Request("/api/v1/reports?period=month"), Request("/api/v1/password-book?page=1&pageSize=20"));
                var data = await Request("/api/v1/credential-evidence/export", JsonContent.Create(new { artifactIds = new[] { "cred-" + 1.ToString("x32") } }));
                if (data is { } result && result.GetProperty("items")[0].GetProperty("outcome").GetString() != "OK")
                    Errors.AddOrUpdate("historical evidence export", 1, (_, n) => n + 1);
            } while (await timer.WaitForNextTickAsync(stopping));
        }
        catch (OperationCanceledException) when (stopping.IsCancellationRequested) { }
    }
}
