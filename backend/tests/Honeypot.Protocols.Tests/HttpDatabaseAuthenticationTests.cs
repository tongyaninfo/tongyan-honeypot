using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Elastic.Clients.Elasticsearch;
using Elastic.Transport;
using Honeypot.Protocol.Abstractions.Service;
using Honeypot.Protocols.Elasticsearch;
using Honeypot.Protocols.InfluxDb;
using InfluxDB.Client;
using Xunit;

namespace Honeypot.Protocols.Tests;

public sealed class HttpDatabaseAuthenticationTests
{
    [Fact]
    public async Task OfficialElasticClientRecognizesAuthenticationFailure()
    {
        await using var server = new AuthenticationTestServer(new ElasticsearchAdapter(), AuthenticationTestServer.Profile("elasticsearch"));
        var settings = new ElasticsearchClientSettings(new Uri($"http://127.0.0.1:{server.Port}"))
            .Authentication(new BasicAuthentication("test-user", "elastic-isolated-password"));
        var client = new ElasticsearchClient(settings);
        var result = await client.InfoAsync();
        Assert.False(result.IsValidResponse);
        Assert.Equal(401, result.ApiCallDetails?.HttpStatusCode);
        Assert.Equal("security_exception", result.ElasticsearchServerError?.Error?.Type);
        var authentication = await server.Sink.Authentication.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal("test-user", authentication.Username);
        Assert.Equal("HTTP_401", authentication.AuthenticationFailureCode);
        using var json = JsonDocument.Parse(Assert.Single(server.Sink.Evidence).Content);
        Assert.Equal("elastic-isolated-password", json.RootElement.GetProperty("password").GetString());
        Assert.DoesNotContain("elastic-isolated-password", JsonSerializer.Serialize(server.Sink.Events));
    }

    [Fact]
    public async Task OfficialInfluxClientRecognizesUnauthorizedAndCapturesTokenAsToken()
    {
        await using var server = new AuthenticationTestServer(new InfluxDbAdapter(), AuthenticationTestServer.Profile("influxdb"));
        using var client = new InfluxDBClient($"http://127.0.0.1:{server.Port}", "influx-isolated-token");
        var error = await Record.ExceptionAsync(() => client.GetBucketsApi().FindBucketsAsync());
        Assert.NotNull(error);
        Assert.Contains("Unauthorized", error.GetType().Name, StringComparison.OrdinalIgnoreCase);
        var authentication = await server.Sink.Authentication.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal("Token", authentication.MaterialType);
        using var json = JsonDocument.Parse(Assert.Single(server.Sink.Evidence).Content);
        Assert.Equal("influx-isolated-token", json.RootElement.GetProperty("token").GetString());
        Assert.False(json.RootElement.TryGetProperty("password", out _));
        Assert.DoesNotContain("influx-isolated-token", JsonSerializer.Serialize(server.Sink.Events));
    }

    [Theory]
    [InlineData(false, "")]
    [InlineData(true, "isolated-雪")]
    public async Task InfluxV1BasicOverHttpAndTlsPreservesActualPassword(bool tls, string password)
    {
        await using var server = new AuthenticationTestServer(new InfluxDbAdapter(), AuthenticationTestServer.Profile("influxdb") with { InfluxDbApiVersion = "v1" });
        // 隔离进程内测试证书不进入宿主信任仓库。
        using var handler = new HttpClientHandler { ServerCertificateCustomValidationCallback = (_, _, _, _) => true };
        using var client = new HttpClient(handler);
        using var request = new HttpRequestMessage(System.Net.Http.HttpMethod.Get, $"{(tls ? "https" : "http")}://127.0.0.1:{server.Port}/query?q=SHOW+DATABASES");
        request.Headers.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes("隔离用户:" + password)));
        using var response = await client.SendAsync(request);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        var authentication = await server.Sink.Authentication.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal("隔离用户", authentication.Username);
        using var json = JsonDocument.Parse(Assert.Single(server.Sink.Evidence).Content);
        Assert.Equal(password, json.RootElement.GetProperty("password").GetString());
        Assert.Empty(server.Errors);
    }

    [Fact]
    public async Task HealthProbeIsNotAuthenticationAndEachRetryIsOneAttempt()
    {
        await using var server = new AuthenticationTestServer(new InfluxDbAdapter(), AuthenticationTestServer.Profile("influxdb"));
        using var client = new HttpClient { BaseAddress = new Uri($"http://127.0.0.1:{server.Port}") };
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Token", "isolate-token");
        using var health = await client.GetAsync("/ping");
        Assert.Equal(HttpStatusCode.NoContent, health.StatusCode);
        Assert.False(health.Content.Headers.Contains("Content-Length"));
        Assert.Empty(server.Sink.Evidence);
        for (var i = 0; i < 2; i++) Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/api/v2/buckets")).StatusCode);
        Assert.Equal(2, server.Sink.Events.Count(x => x.EventType == "AuthenticationAttempted"));
        Assert.Equal(2, server.Sink.Evidence.Count);
    }

    [Fact]
    public async Task InfluxV1TokenPasswordIsNotMistakenForV2ApiToken()
    {
        await using var server = new AuthenticationTestServer(new InfluxDbAdapter(), AuthenticationTestServer.Profile("influxdb") with { InfluxDbApiVersion = "v1" });
        using var client = new HttpClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Token", "sample:isolated-v1-password");
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync($"http://127.0.0.1:{server.Port}/query?q=SHOW+DATABASES")).StatusCode);
        using var json = JsonDocument.Parse(Assert.Single(server.Sink.Evidence).Content);
        Assert.Equal("isolated-v1-password", json.RootElement.GetProperty("password").GetString());
        Assert.Equal("Plaintext", Assert.Single(server.Sink.Events, x => x.EventType == "AuthenticationAttempted").MaterialType);
    }

    [Theory]
    [InlineData("Authorization: Basic dTpw\r\nAuthorization: Basic eDp5\r\n")]
    [InlineData("Content-Length: 0\r\nTransfer-Encoding: chunked\r\n")]
    [InlineData("Content-Length: 2147483647\r\n")]
    public async Task AmbiguousOrOversizeRequestsCannotBecomeAuthentication(string headers)
    {
        var session = new AuthenticationByteSession(Encoding.ASCII.GetBytes($"GET / HTTP/1.1\r\nHost: localhost\r\n{headers}\r\n"), 1);
        var sink = new AuthenticationRecordingSink();
        await new ElasticsearchAdapter().HandleAsync(session, AuthenticationTestServer.Context("elasticsearch"), AuthenticationTestServer.Profile("elasticsearch"), sink);
        Assert.Empty(sink.Evidence);
        Assert.Contains(sink.Events, x => x.EventType == "ProtocolViolation");
        Assert.DoesNotContain(sink.Events, x => x.EventType == "AuthenticationAttempted");
    }

    [Fact]
    public async Task ChunkedBodyAndQueryCredentialsAreBoundedAndNotLogged()
    {
        var session = new AuthenticationByteSession(Encoding.ASCII.GetBytes("POST /query?u=demo&p=query-isolated-secret HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n3\r\na=b\r\n0\r\n\r\n"), 1);
        var sink = new AuthenticationRecordingSink();
        await new InfluxDbAdapter().HandleAsync(session, AuthenticationTestServer.Context("influxdb"), AuthenticationTestServer.Profile("influxdb") with { InfluxDbApiVersion = "v1" }, sink);
        Assert.Single(sink.Events, x => x.EventType == "AuthenticationAttempted");
        using var json = JsonDocument.Parse(Assert.Single(sink.Evidence).Content);
        Assert.Equal("query-isolated-secret", json.RootElement.GetProperty("password").GetString());
        Assert.DoesNotContain("query-isolated-secret", JsonSerializer.Serialize(sink.Events));
    }

    [Fact]
    public async Task StorageFailureNeverReturnsNormalAuthenticationFailure()
    {
        await using var server = new AuthenticationTestServer(new ElasticsearchAdapter(), AuthenticationTestServer.Profile("elasticsearch"), failStorage: true);
        using var client = new HttpClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes("demo:sample")));
        await Assert.ThrowsAsync<HttpRequestException>(() => client.GetAsync($"http://127.0.0.1:{server.Port}/"));
        Assert.Empty(server.Sink.Evidence);
        Assert.DoesNotContain(server.Sink.Events, x => x.EventType == "AuthenticationAttempted");
    }
}
