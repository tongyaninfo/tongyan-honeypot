using System.Collections.Concurrent;
using Honeypot.Engine.Models;
using Honeypot.Protocol.Abstractions.Models;

namespace Honeypot.Engine.Service.impl;

/// <summary>
/// 一期内存聚合实现，保证连接事件到威胁清单的同步可见性；生产持久化由独立存储实现替换。
/// </summary>
public sealed class InMemoryThreatProfileStore : IThreatProfileStore
{
    private readonly ConcurrentDictionary<string, ThreatIpProfile> _profiles = new(StringComparer.OrdinalIgnoreCase);

    public ThreatIpProfile Apply(InteractionEvent interactionEvent)
    {
        ArgumentNullException.ThrowIfNull(interactionEvent);

        var profile = _profiles.GetOrAdd(interactionEvent.SourceIp, sourceIp => new ThreatIpProfile
        {
            ThreatId = $"threat-{Guid.NewGuid():N}",
            SourceIp = sourceIp,
            FirstSeenUtc = interactionEvent.OccurredAtUtc,
            LastSeenUtc = interactionEvent.OccurredAtUtc,
        });

        lock (profile)
        {
            profile.LastSeenUtc = interactionEvent.OccurredAtUtc;
            profile.LastEventId = interactionEvent.EventId;
            profile.AttemptCount++;
            profile.ServicesTouched.Add(interactionEvent.AdapterKey);
            profile.PortsTouched.Add(interactionEvent.DestinationPort);

            var delta = Math.Max(0, interactionEvent.RiskDelta);
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

            if (profile.PortsTouched.Count > 1)
            {
                delta += 3;
            }

            profile.CurrentScore = Math.Min(100, profile.CurrentScore + delta);
            profile.MaxScore = Math.Max(profile.MaxScore, profile.CurrentScore);
            profile.Status = profile.CurrentScore >= 20 ? "Suspicious" : "Observed";
            profile.LastReason = interactionEvent.PayloadSummary;
            return profile;
        }
    }

    public IReadOnlyCollection<ThreatIpProfile> GetAll() => _profiles.Values
        .OrderByDescending(item => item.LastSeenUtc)
        .ToArray();

    public ThreatIpProfile? GetByIp(string sourceIp) =>
        _profiles.TryGetValue(sourceIp, out var profile) ? profile : null;
}
