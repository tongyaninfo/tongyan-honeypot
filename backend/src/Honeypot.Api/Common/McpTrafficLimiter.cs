using System.Diagnostics;

namespace Honeypot.Api.Common;

internal sealed class McpTrafficLimiter
{
    private const int PartitionLimit = 4096;
    private readonly object gate = new();
    private readonly Dictionary<string, Window> partitions = new(StringComparer.Ordinal);
    private readonly Window global = new();
    private readonly Window rejectedAudit = new();
    private long lastSweep;

    public IDisposable? EnterSource(string source) => Enter("ip:" + source, 120, 8, includeGlobal: true);
    public IDisposable? EnterKey(string keyId) => Enter("key:" + keyId, 60, 4, includeGlobal: false);

    public bool TryRecordRejectedRequest()
    {
        lock (gate)
        {
            Reset(rejectedAudit, Stopwatch.GetTimestamp());
            if (rejectedAudit.Requests >= 120) return false;
            rejectedAudit.Requests++;
            return true;
        }
    }

    private IDisposable? Enter(string key, int perMinute, int concurrent, bool includeGlobal)
    {
        lock (gate)
        {
            var now = Stopwatch.GetTimestamp();
            if (Stopwatch.GetElapsedTime(lastSweep, now) >= TimeSpan.FromMinutes(1))
            {
                foreach (var item in partitions.Where(item => item.Value.Active == 0 &&
                    Stopwatch.GetElapsedTime(item.Value.Since, now) >= TimeSpan.FromMinutes(1)).ToArray())
                    partitions.Remove(item.Key);
                lastSweep = now;
            }

            Reset(global, now);
            if (includeGlobal && (global.Active >= 24 || global.Requests >= 360)) return null;
            if (!partitions.TryGetValue(key, out var window))
            {
                if (partitions.Count >= PartitionLimit) return null;
                partitions.Add(key, window = new Window());
            }
            Reset(window, now);
            if (window.Active >= concurrent || window.Requests >= perMinute) return null;
            window.Requests++;
            window.Active++;
            if (includeGlobal)
            {
                global.Requests++;
                global.Active++;
            }
            return new Lease(this, window, includeGlobal);
        }
    }

    private static void Reset(Window window, long now)
    {
        if (Stopwatch.GetElapsedTime(window.Since, now) < TimeSpan.FromMinutes(1)) return;
        window.Since = now;
        window.Requests = 0;
    }

    private sealed class Window
    {
        public long Since;
        public int Requests;
        public int Active;
    }

    private sealed class Lease(McpTrafficLimiter owner, Window window, bool includeGlobal) : IDisposable
    {
        public void Dispose()
        {
            lock (owner.gate)
            {
                window.Active--;
                if (includeGlobal) owner.global.Active--;
            }
        }
    }
}
