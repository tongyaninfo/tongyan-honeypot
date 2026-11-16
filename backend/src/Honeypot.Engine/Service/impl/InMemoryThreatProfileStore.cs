using Honeypot.Engine.Models;
using Honeypot.Protocol.Abstractions.Models;

namespace Honeypot.Engine.Service.impl;

/// <summary>
/// 隔离运行和测试使用的内存聚合实现。
/// </summary>
public sealed class InMemoryThreatProfileStore(int capacity = 10_000, TimeSpan? retention = null, TimeProvider? time = null) : IThreatProfileStore
{
    private readonly Dictionary<string, LinkedListNode<Entry>> _profiles = new(StringComparer.OrdinalIgnoreCase);
    private readonly LinkedList<Entry> _activity = new();
    private readonly object _gate = new();
    private readonly TimeProvider _clock = time ?? TimeProvider.System;
    private readonly TimeSpan _retention = retention ?? TimeSpan.FromHours(24);

    public ThreatIpProfile Apply(InteractionEvent interactionEvent) => Apply(interactionEvent, out _);

    public ThreatIpProfile Apply(InteractionEvent interactionEvent, out string? previousStatus)
    {
        ArgumentNullException.ThrowIfNull(interactionEvent);

        lock (_gate)
        {
            var now = _clock.GetTimestamp();
            EvictExpired(now);
            if (!_profiles.TryGetValue(interactionEvent.SourceIp, out var node))
            {
                previousStatus = null;
                if (_profiles.Count >= capacity) EvictOldest();
                node = _activity.AddLast(new Entry(new ThreatIpProfile
                {
                    ThreatId = $"threat-{Guid.NewGuid():N}",
                    SourceIp = interactionEvent.SourceIp,
                    FirstSeenUtc = interactionEvent.OccurredAtUtc,
                    LastSeenUtc = interactionEvent.OccurredAtUtc,
                }, now));
                _profiles.Add(interactionEvent.SourceIp, node);
            }
            else
            {
                previousStatus = node.Value.Profile.Status;
                _activity.Remove(node);
                node.Value = node.Value with { LastActivity = now };
                _activity.AddLast(node);
            }
            var profile = node.Value.Profile;
            ThreatProfileAggregation.Apply(profile, interactionEvent, _clock.GetUtcNow().Add(_retention));
            return Snapshot(profile);
        }
    }

    public IReadOnlyCollection<ThreatIpProfile> GetAll()
    {
        ThreatIpProfile[] profiles;
        lock (_gate)
        {
            EvictExpired(_clock.GetTimestamp());
            profiles = _activity.Select(entry => Snapshot(entry.Profile)).ToArray();
        }
        return profiles.OrderByDescending(item => item.LastSeenUtc).ToArray();
    }

    public ThreatIpProfile? GetByIp(string sourceIp)
    {
        lock (_gate)
        {
            EvictExpired(_clock.GetTimestamp());
            return _profiles.TryGetValue(sourceIp, out var node) ? Snapshot(node.Value.Profile) : null;
        }
    }

    private void EvictExpired(long now)
    {
        while (_activity.First is { } node && _clock.GetElapsedTime(node.Value.LastActivity, now) >= _retention)
            EvictOldest();
    }

    private void EvictOldest()
    {
        if (_activity.First is not { } oldest) return;
        _activity.RemoveFirst();
        _profiles.Remove(oldest.Value.Profile.SourceIp);
    }

    private static ThreatIpProfile Snapshot(ThreatIpProfile source)
    {
        // 复制集合，避免序列化时与新的协议或端口更新交叉。
        var result = new ThreatIpProfile
        {
            ThreatId = source.ThreatId,
            SourceIp = source.SourceIp,
            FirstSeenUtc = source.FirstSeenUtc,
            LastSeenUtc = source.LastSeenUtc,
            CurrentScore = source.CurrentScore,
            MaxScore = source.MaxScore,
            ScoreVersion = source.ScoreVersion,
            Status = source.Status,
            AttemptCount = source.AttemptCount,
            SessionCount = source.SessionCount,
            ActiveSessionCount = source.ActiveSessionCount,
            AuthenticationAttemptCount = source.AuthenticationAttemptCount,
            ProtocolViolationCount = source.ProtocolViolationCount,
            LastEventId = source.LastEventId,
            LastReason = source.LastReason,
            ExpiresAtUtc = source.ExpiresAtUtc,
        };
        result.ServicesTouched.UnionWith(source.ServicesTouched);
        result.PortsTouched.UnionWith(source.PortsTouched);
        return result;
    }

    private sealed record Entry(ThreatIpProfile Profile, long LastActivity);
}
