using Honeypot.Protocol.Abstractions.Models;

namespace Honeypot.Api.Service;

/// <summary>
/// 向已鉴权管理台广播运行时变化。广播失败不能阻断事件落库或监听器运行。
/// </summary>
public interface IRealtimeUpdateNotifier
{
    Task PublishEventAsync(InteractionEvent interactionEvent, CancellationToken cancellationToken = default);

    Task PublishRuntimeAsync(
        IReadOnlyCollection<ListenerRuntimeStatus> statuses,
        CancellationToken cancellationToken = default);
}
