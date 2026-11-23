using System.Net;
using Honeypot.Runtime.Models;
using Honeypot.Runtime.Options;

namespace Honeypot.Runtime.Common;

/// <summary>一次锁内校验并预留所有额度，避免多个监听间重复计数或漏计。</summary>
internal sealed class ConnectionAdmission(ConnectionAdmissionOptions options, TimeProvider clock)
{
    private static readonly TimeSpan RateWindow = TimeSpan.FromSeconds(1);
    private readonly object _gate = new();
    private readonly Dictionary<IPAddress, SourceWindow> _sources = new();
    private long _windowStart = clock.GetTimestamp();
    private int _active;
    private int _started;

    /// <summary>成功预留连接额度时返回 null；其他情况返回可写入连接记录的固定拒绝原因。</summary>
    public string? TryEnter(RuntimeListener listener, IPAddress source)
    {
        lock (_gate)
        {
            var now = clock.GetTimestamp();
            if (clock.GetElapsedTime(_windowStart, now) >= RateWindow)
                StartWindow(now);

            if (_active >= options.MaxConcurrentConnections) return "global_concurrency";
            if (_started >= options.MaxNewConnectionsPerSecond) return "global_rate";
            if (listener.ActiveConnections >= listener.Binding.MaxConnections) return "listener_concurrency";
            if (listener.ConnectionsByIp.GetValueOrDefault(source) >= listener.Binding.MaxConnectionsPerIp)
                return "listener_source_concurrency";

            if (!_sources.TryGetValue(source, out var entry))
            {
                // 表满时直接拒绝新来源，避免通过来源轮换制造额外分配或重置已有来源计数。
                if (_sources.Count >= options.MaxTrackedSources) return "tracked_sources";
                _sources.Add(source, entry = new SourceWindow());
            }
            if (entry.Active >= options.MaxConcurrentConnectionsPerSource) return "source_concurrency";
            if (entry.Started >= options.MaxNewConnectionsPerSourcePerSecond) return "source_rate";

            _active++;
            _started++;
            entry.Active++;
            entry.Started++;
            listener.ConnectionsByIp[source] = listener.ConnectionsByIp.GetValueOrDefault(source) + 1;
            Interlocked.Increment(ref listener.ActiveConnections);
            return null;
        }
    }

    public void Exit(RuntimeListener listener, IPAddress source)
    {
        lock (_gate)
        {
            _active--;
            _sources[source].Active--;
            var remaining = listener.ConnectionsByIp[source] - 1;
            if (remaining == 0) listener.ConnectionsByIp.Remove(source);
            else listener.ConnectionsByIp[source] = remaining;
            Interlocked.Decrement(ref listener.ActiveConnections);
        }
    }

    private void StartWindow(long timestamp)
    {
        _windowStart = timestamp;
        _started = 0;
        foreach (var (source, entry) in _sources)
        {
            // Dictionary.Remove 支持 .NET 10 对当前字典的枚举。活跃来源保留并发计数。
            if (entry.Active == 0) _sources.Remove(source);
            else entry.Started = 0;
        }
    }

    private sealed class SourceWindow
    {
        public int Active;
        public int Started;
    }
}
