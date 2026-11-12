namespace Honeypot.Api.Options;

internal sealed class McpTransportOptions
{
    public string[] AllowedHosts { get; set; } = [];
    public string[] TrustedProxies { get; set; } = [];
    public string[] InsecureHttpNetworks { get; set; } = [];
}
