using Honeypot.Api.Models;
using Honeypot.Protocol.Abstractions.Models;

namespace Honeypot.Api.Common;

/// <summary>将协议步骤投影为可读行为；原始事件保留在连接详情，不能按来源 IP/时间猜测并合并不同登录。</summary>
public static class InteractionActivityProjection
{
    public static IReadOnlyCollection<RealtimeInteractionEvent> Build(IEnumerable<InteractionEvent> events)
    {
        var activities = new List<RealtimeInteractionEvent>();
        foreach (var connection in events.GroupBy(item => item.ConnectionId, StringComparer.OrdinalIgnoreCase))
        {
            var steps = connection.OrderBy(item => item.Sequence).ThenBy(item => item.OccurredAtUtc).ToArray();
            var authentications = steps.Where(item => IsType(item, "AuthenticationAttempted") || IsType(item, "AuthorizationDenied")).ToArray();
            if (authentications.Length > 0)
            {
                // 认证提交与无密码协议的访问拒绝均为业务行为；分别保留且不虚增认证次数。
                activities.AddRange(authentications.Select(item =>
                    RealtimeInteractionEvent.From(item) with { EventCount = steps.Length }));
                continue;
            }

            // 未到认证阶段的连接也需可见；优先显示故障原因，而非把最后的 SessionClosed 当作威胁。
            var representative = steps.LastOrDefault(item => IsType(item, "StorageDegraded") || IsType(item, "CredentialCaptureFailed") || IsType(item, "AuthenticationEventWriteFailed"))
                ?? steps.LastOrDefault(item => IsType(item, "ProtocolViolation") || IsType(item, "HandshakeTimeout") || IsType(item, "AuthenticationRequired") || IsType(item, "CaptureTruncated") || IsType(item, "ResourceLimitExceeded") || IsType(item, "RuleMatched"))
                ?? steps.FirstOrDefault(item => IsType(item, "ConnectionAccepted"))
                ?? steps[^1];
            activities.Add(RealtimeInteractionEvent.From(representative) with { EventCount = steps.Length });
        }

        return activities.OrderByDescending(item => item.OccurredAtUtc)
            .ThenByDescending(item => item.Sequence)
            .ThenBy(item => item.EventId, StringComparer.Ordinal)
            .ToArray();
    }

    private static bool IsType(InteractionEvent item, string type) =>
        item.EventType.Equals(type, StringComparison.OrdinalIgnoreCase);
}
