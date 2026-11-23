using Honeypot.Api.Models;
using Honeypot.Protocol.Abstractions.Models;

namespace Honeypot.Api.Common;

/// <summary>将协议步骤投影为可读行为；原始事件保留在连接详情，不能按来源 IP/时间猜测并合并不同登录。</summary>
public static class InteractionActivityProjection
{
    internal const int Accepted = 1;
    internal const int Authentication = 4;

    public static IReadOnlyCollection<RealtimeInteractionEvent> Build(IEnumerable<InteractionEvent> events)
    {
        var activities = new List<RealtimeInteractionEvent>();
        foreach (var connection in events.GroupBy(item => item.ConnectionId, StringComparer.OrdinalIgnoreCase))
        {
            var steps = connection.OrderBy(item => item.Sequence).ThenBy(item => item.OccurredAtUtc).ToArray();
            var authentications = steps.Where(item => Priority(item.EventType) == Authentication).ToArray();
            if (authentications.Length > 0)
            {
                // 认证提交与无密码协议的访问拒绝均为业务行为；分别保留且不虚增认证次数。
                activities.AddRange(authentications.Select(item =>
                    RealtimeInteractionEvent.From(item) with { EventCount = steps.Length }));
                continue;
            }

            // 未到认证阶段的连接也需可见；优先显示故障原因，而非把最后的 SessionClosed 当作威胁。
            var priority = steps.Max(item => Priority(item.EventType));
            var representative = priority == Accepted
                ? steps.First(item => Priority(item.EventType) == Accepted)
                : steps.Last(item => Priority(item.EventType) == priority);
            activities.Add(RealtimeInteractionEvent.From(representative) with { EventCount = steps.Length });
        }

        return activities.OrderByDescending(item => item.OccurredAtUtc)
            .ThenByDescending(item => item.Sequence)
            .ThenBy(item => item.EventId, StringComparer.Ordinal)
            .ToArray();
    }

    internal static int Priority(string type) => type.ToLowerInvariant() switch
    {
        "authenticationattempted" or "authorizationdenied" => Authentication,
        "storagedegraded" or "credentialcapturefailed" or "authenticationeventwritefailed" => 3,
        "protocolviolation" or "handshaketimeout" or "authenticationrequired" or "capturetruncated" or
            "resourcelimitexceeded" or "rulematched" => 2,
        "connectionaccepted" or "connectionrejected" => Accepted,
        _ => 0,
    };
}
