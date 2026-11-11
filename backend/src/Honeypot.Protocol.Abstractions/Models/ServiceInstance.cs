namespace Honeypot.Protocol.Abstractions.Models;

/// <summary>
/// 一个逻辑服务及其人格和监听端口集合。
/// </summary>
public sealed record ServiceInstance
{
    public required string InstanceId { get; init; }
    public required string DisplayName { get; init; }
    public required string AdapterKey { get; init; }
    public required ServiceProfile Profile { get; init; }
    public IReadOnlyList<ListenerBinding> Bindings { get; init; } = Array.Empty<ListenerBinding>();

    /// <summary>管理员期望的下一次运行状态；重启恢复时不会直接信任运行态。</summary>
    public string DesiredState { get; init; } = "Stopped";

    /// <summary>是否在应用启动后自动恢复监听。</summary>
    public bool AutoStart { get; init; }

    /// <summary>最近一次由运行时确认的实际状态。</summary>
    public string CurrentState { get; init; } = "Stopped";

    /// <summary>最近一次启动/恢复失败原因。</summary>
    public string? LastError { get; init; }
}
