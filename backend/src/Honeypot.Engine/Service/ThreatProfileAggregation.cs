using Honeypot.Engine.Models;
using Honeypot.Protocol.Abstractions.Models;

namespace Honeypot.Engine.Service;

/// <summary>威胁评分与计数规则由 Engine 统一维护，调用方负责事件去重和原子保存。</summary>
public static class ThreatProfileAggregation
{
    public static void Apply(ThreatIpProfile profile, InteractionEvent interactionEvent, DateTimeOffset expiresAtUtc)
    {
        if (interactionEvent.OccurredAtUtc > profile.LastSeenUtc) profile.LastSeenUtc = interactionEvent.OccurredAtUtc;
        if (interactionEvent.OccurredAtUtc < profile.FirstSeenUtc) profile.FirstSeenUtc = interactionEvent.OccurredAtUtc;
        profile.ExpiresAtUtc = expiresAtUtc;
        profile.LastEventId = interactionEvent.EventId;
        profile.AttemptCount++;
        // 单个来源持续活跃时，协议和端口集合仍保持有界。
        if (profile.ServicesTouched.Count < 32) profile.ServicesTouched.Add(interactionEvent.AdapterKey);
        if (profile.PortsTouched.Count < 128) profile.PortsTouched.Add(interactionEvent.DestinationPort);

        var delta = Math.Clamp(interactionEvent.RiskDelta, 0, 100);
        if (interactionEvent.EventType.Equals("AuthenticationAttempted", StringComparison.OrdinalIgnoreCase))
        {
            profile.AuthenticationAttemptCount++;
            delta += 5;
        }

        if (interactionEvent.EventType.Equals("ProtocolViolation", StringComparison.OrdinalIgnoreCase))
        {
            profile.ProtocolViolationCount++;
            delta += 4;
        }

        if (profile.PortsTouched.Count > 1) delta += 3;

        profile.CurrentScore += Math.Clamp(delta, 0, 100 - profile.CurrentScore);
        profile.MaxScore = Math.Max(profile.MaxScore, profile.CurrentScore);
        profile.Status = profile.CurrentScore >= 20 ? "Suspicious" : "Observed";
        profile.LastReason = interactionEvent.PayloadSummary;
    }
}
