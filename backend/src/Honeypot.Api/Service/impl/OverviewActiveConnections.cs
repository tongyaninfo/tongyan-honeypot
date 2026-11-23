using Honeypot.Protocol.Abstractions.Models;
using Honeypot.Protocol.Abstractions.Service;

namespace Honeypot.Api.Service.impl;

/// <summary>保存首页实际采样的活动连接；关闭后翻页仍可重现当时卡片的数字。</summary>
public sealed class OverviewActiveConnections(TimeProvider clock, IListenerHost listeners)
{
    private static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(5);
    private readonly Dictionary<DateTimeOffset, Snapshot> _snapshots = [];
    private readonly object _gate = new();
    private Snapshot? _latest;

    public sealed record Snapshot(DateTimeOffset AsOfUtc, IReadOnlyList<ActiveConnectionSnapshot> Items);

    public Snapshot Capture()
    {
        lock (_gate)
        {
            var now = clock.GetUtcNow();
            if (_latest is not null && now >= _latest.AsOfUtc && now < _latest.AsOfUtc.AddSeconds(1))
                return _latest;

            // 多个管理台一秒内复用同一次采样。只在重新采样时清理过期快照。
            foreach (var key in _snapshots.Keys.Where(key => now - key >= Lifetime || key > now).ToArray())
                _snapshots.Remove(key);
            _latest = new(now, listeners.GetActiveConnections().ToArray());
            _snapshots[now] = _latest;
            return _latest;
        }
    }

    public Snapshot? Find(DateTimeOffset asOfUtc)
    {
        lock (_gate)
        {
            var now = clock.GetUtcNow();
            return now >= asOfUtc && now - asOfUtc < Lifetime ? _snapshots.GetValueOrDefault(asOfUtc) : null;
        }
    }
}
