using System.Text.Json;
using Honeypot.Protocol.Abstractions.Models;
using Honeypot.Protocols.Common;

namespace Honeypot.Protocols.InfluxDb;

/// <summary>InfluxDB v1/v2 认证入口；公开健康检查可用，所有带权限的操作均返回标准 401。</summary>
public sealed class InfluxDbAdapter : HttpDatabaseAdapterBase
{
    public override ServiceAdapterDescriptor Descriptor { get; } = new()
    {
        AdapterKey = "influxdb", DisplayName = "InfluxDB", SupportedFidelityLevels = ["L0", "L1", "L2", "L3"],
        SupportedClients = ["InfluxDB.Client (v2)", "HTTP/1.1 (v1/v2)"],
    };
    public override async ValueTask<AdapterValidationResult> ValidateAsync(ServiceProfile profile, CancellationToken cancellationToken = default)
    {
        var result = await base.ValidateAsync(profile, cancellationToken);
        return result.IsValid && profile.InfluxDbApiVersion is not ("v1" or "v2")
            ? AdapterValidationResult.Invalid("UNSUPPORTED_INFLUX_VERSION", "only v1 and v2 are supported") : result;
    }

    protected override HttpAuthenticationMaterial? Authentication(ProtocolHttpRequest request, ServiceProfile profile)
    {
        // 健康探测不执行认证；即使客户端预发 Authorization 也不虚增失败数。
        if (IsHealth(request)) return null;
        var v2 = profile.InfluxDbApiVersion == "v2";
        // v1 的 Token username:password 与 v2 不透明 API token 是不同机制。
        if (!v2 && request.Headers.TryGetValue("Authorization", out var value) && value.StartsWith("Token ", StringComparison.OrdinalIgnoreCase))
        {
            var text = value[6..].Trim();
            var colon = text.IndexOf(':');
            if (colon >= 0)
                return new(text[..colon], "HTTP-Token-Password", "Plaintext",
                    JsonSerializer.SerializeToUtf8Bytes(new { username = text[..colon], password = text[(colon + 1)..] }));
        }
        var header = HeaderAuthentication(request, basicIsToken: v2 && request.Path != "/api/v2/signin");
        if (header is not null) return header;
        var query = QueryParameters(request.Target);
        if (!query.TryGetValue("u", out var user) && !query.ContainsKey("p")) return null;
        var password = query.GetValueOrDefault("p", "");
        return v2
            ? new(user, "HTTP-Query-Token", "Token", JsonSerializer.SerializeToUtf8Bytes(new { username = user, token = password }))
            : new(user, "HTTP-Query", "Plaintext", JsonSerializer.SerializeToUtf8Bytes(new { username = user, password }));
    }

    protected override ProtocolHttpResponse Response(ProtocolHttpRequest request, ServiceProfile profile, bool attempted)
    {
        var v2 = profile.InfluxDbApiVersion == "v2";
        var version = v2 ? ProtocolFingerprint.Version(profile) : "1.8.10";
        var headers = new List<KeyValuePair<string, string>> { new("X-Influxdb-Version", version), new("X-Influxdb-Build", "OSS") };
        if (IsHealth(request))
            return request.Path == "/ping" ? new(204, "", headers)
                : new(200, JsonSerializer.Serialize(new { name = "influxdb", message = "ready for queries and writes", status = "pass", version, checks = Array.Empty<object>() }), headers);
        if (v2 && request.Path.StartsWith("/api/v2/", StringComparison.Ordinal))
            return new(401, "{\"code\":\"unauthorized\",\"message\":\"unauthorized access\"}", headers);
        headers.Add(new("WWW-Authenticate", "Basic realm=\"InfluxDB\""));
        return new(401, JsonSerializer.Serialize(new { error = attempted ? "authorization failed" : "unable to parse authentication credentials" }), headers);
    }

    private static bool IsHealth(ProtocolHttpRequest request) => request.Method is "GET" or "HEAD" && request.Path is "/ping" or "/health";
}
