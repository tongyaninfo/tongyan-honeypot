namespace Honeypot.Api.Data.Models;

/// <summary>
/// 服务实例持久化模型。协议人格以 JSON 快照保存，避免数据库模型耦合每个适配器的字段。
/// </summary>
public sealed class ServiceInstanceEntity
{
    public required string InstanceId { get; set; }
    public required string DisplayName { get; set; }
    public required string AdapterKey { get; set; }
    public required string ProfileJson { get; set; }
    public required string DesiredState { get; set; }
    public bool AutoStart { get; set; }
    public required string CurrentState { get; set; }
    public string? LastError { get; set; }
    public DateTimeOffset CreatedAtUtc { get; set; }
    public DateTimeOffset UpdatedAtUtc { get; set; }
    public List<ListenerBindingEntity> Bindings { get; set; } = new();
}
