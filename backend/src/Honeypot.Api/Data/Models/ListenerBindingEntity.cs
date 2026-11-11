namespace Honeypot.Api.Data.Models;

/// <summary>实例端口绑定的持久化模型。</summary>
public sealed class ListenerBindingEntity
{
    public required string ListenerId { get; set; }
    public required string InstanceId { get; set; }
    public required string BindAddress { get; set; }
    public int Port { get; set; }
    public required string Transport { get; set; }
    public bool Enabled { get; set; }
    public int MaxConnections { get; set; }
    public int MaxConnectionsPerIp { get; set; }
    public ServiceInstanceEntity? Instance { get; set; }
}
