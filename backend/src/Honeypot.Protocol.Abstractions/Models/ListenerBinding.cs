namespace Honeypot.Protocol.Abstractions.Models;

/// <summary>
/// 服务实例的单个监听入口。同一实例可以绑定多个端口。
/// </summary>
public sealed record ListenerBinding
{
    public required string ListenerId { get; init; }
    public string BindAddress { get; init; } = "0.0.0.0";
    public required int Port { get; init; }
    public string Transport { get; init; } = "tcp";
    public bool Enabled { get; init; } = true;
    public int MaxConnections { get; init; } = 200;
    public int MaxConnectionsPerIp { get; init; } = 10;
}
