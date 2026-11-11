using Honeypot.Protocol.Abstractions.Service;

namespace Honeypot.Runtime.Service;

/// <summary>
/// 初始化阶段的本地 ID 实现。生产环境通过 DI 替换为项目集中 ID 服务。
/// </summary>
public sealed class ConnectionIdGenerator : IConnectionIdGenerator
{
    public string NewConnectionId() => $"conn_{Guid.NewGuid():N}";

    public string NewEventId() => $"evt_{Guid.NewGuid():N}";
}
