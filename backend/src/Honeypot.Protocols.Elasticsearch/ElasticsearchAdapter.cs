using System.Text.Json;
using Honeypot.Protocol.Abstractions.Models;
using Honeypot.Protocols.Common;

namespace Honeypot.Protocols.Elasticsearch;

/// <summary>Elasticsearch REST 安全认证失败，保留官方客户端的产品识别头，不执行任何查询。</summary>
public sealed class ElasticsearchAdapter : HttpDatabaseAdapterBase
{
    public override ServiceAdapterDescriptor Descriptor { get; } = new()
    {
        AdapterKey = "elasticsearch", DisplayName = "Elasticsearch", SupportedFidelityLevels = ["L0", "L1", "L2", "L3"],
        SupportedClients = ["Elastic.Clients.Elasticsearch", "HTTP/1.1 Basic/ApiKey/Bearer"],
    };
    protected override HttpAuthenticationMaterial? Authentication(ProtocolHttpRequest request, ServiceProfile profile) => HeaderAuthentication(request);

    protected override ProtocolHttpResponse Response(ProtocolHttpRequest request, ServiceProfile profile, bool attempted)
    {
        // 不将含密码查询串或不可信认证头拼入错误响应与普通事件。
        var reason = attempted ? "unable to authenticate with the supplied credentials" : "missing authentication credentials";
        var challenges = new[] { "Basic realm=\"security\" charset=\"UTF-8\"", "Bearer realm=\"security\"", "ApiKey" };
        var error = new
        {
            root_cause = new[] { new { type = "security_exception", reason } },
            type = "security_exception", reason,
            header = new Dictionary<string, object> { ["WWW-Authenticate"] = challenges },
        };
        var headers = new List<KeyValuePair<string, string>> { new("X-Elastic-Product", "Elasticsearch") };
        headers.AddRange(challenges.Select(value => new KeyValuePair<string, string>("WWW-Authenticate", value)));
        return new(401, JsonSerializer.Serialize(new { error, status = 401 }), headers);
    }
}
