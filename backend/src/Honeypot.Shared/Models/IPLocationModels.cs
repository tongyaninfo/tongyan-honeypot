namespace Honeypot.Shared.Models;

/// <summary>通研 IP 适配器配置；默认关闭，启用后才向指定服务发送公网 IP。</summary>
public sealed record IPLocationSettings
{
    public bool Enabled { get; init; }
    public string Protocol { get; init; } = "https";
    public string Host { get; init; } = "ip.tongyaninfo.com";
    public int Port { get; init; } = 443;
    public string Database { get; init; } = "CZ88";
    public double TimeoutSeconds { get; init; } = 2;
}

/// <summary>归属地只使用供应方实际返回的字段，不根据语言或地址猜测行政区。</summary>
public sealed record IPLocationResult(
    string Ip, string Status, string DisplayName = "", string Country = "", string Province = "",
    string City = "", string District = "", string Isp = "");

public sealed record IPLocationBatchRequest(string?[]? Ips);
public sealed record IPLocationBatchResult(bool Enabled, IReadOnlyList<IPLocationResult> Items);
