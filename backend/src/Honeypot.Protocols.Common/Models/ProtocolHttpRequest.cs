namespace Honeypot.Protocols.Common;

/// <summary>请求只在会话内存在；Target/Headers/Body 可能含凭据，禁止写普通日志。</summary>
public sealed record ProtocolHttpRequest(string Method, string Target, string Version,
    IReadOnlyDictionary<string, string> Headers, byte[] Body)
{
    public string Path => Target.Split('?', 2)[0];
    public bool Close => Version == "HTTP/1.0" || Headers.GetValueOrDefault("Connection", "")
        .Split(',').Any(x => x.Trim().Equals("close", StringComparison.OrdinalIgnoreCase));
}

public sealed record ProtocolHttpResponse(int Status, string Body, IReadOnlyList<KeyValuePair<string, string>> Headers);

public sealed record HttpAuthenticationMaterial(string? Username, string Method, string MaterialType, byte[] Content);
