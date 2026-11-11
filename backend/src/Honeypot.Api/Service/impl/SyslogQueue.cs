using System.Collections.Concurrent;
using System.Text;
using System.Threading.Channels;
using Honeypot.Shared.Models;

namespace Honeypot.Api.Service.impl;

public sealed class SyslogQueue(ISyslogSettingsStore settings, IResourceIdGenerator ids, TimeProvider time) : ISyslogPublisher
{
    internal sealed record Pending(SyslogSettingsSnapshot Snapshot, SyslogRecord Record, int Bytes);
    private readonly Channel<Pending> _queue = Channel.CreateBounded<Pending>(new BoundedChannelOptions(100_000)
    {
        SingleReader = true, FullMode = BoundedChannelFullMode.Wait
    });
    private int _bytes;
    private int _count;
    internal ConcurrentDictionary<string, long> Dropped { get; } = new(StringComparer.Ordinal);
    private static readonly HashSet<string> SafeFields = new(StringComparer.OrdinalIgnoreCase)
    {
        "eventId", "connectionId", "sequence", "traceId", "listenerId", "instanceId", "serviceInstanceId",
        "adapterKey", "sourceIp", "sourcePort", "destinationIp", "destinationPort", "actorUserId",
        "username", "domain", "database", "authenticationMethod", "authenticationFailureCode",
        "authenticationAttempt", "materialType", "credentialCaptureStatus", "credentialArtifactId",
        "riskScore", "riskDelta", "closeReason", "persistenceOutcome", "outcome", "eventType", "stage",
        "category", "originalLevel", "eventNumber", "errorCode", "exceptionType", "statusCode",
        "route", "routeKey", "module", "method", "elapsedMs", "count", "state", "decision",
        "auditId", "operation", "kind", "deliveryId", "reportId", "attempt", "targetId", "revision",
        "enabled", "autoStart", "failureCount", "correlationId", "subjectId", "artifactId", "previousState",
        "truncated", "previousStatus", "status", "captureTruncated", "targetCount"
    };

    public void Publish(string appName, string eventCode, SyslogSeverity severity, IReadOnlyDictionary<string, object?>? fields = null)
    {
        var snapshot = settings.DeliverySnapshot;
        if (!snapshot.Settings.Enabled || !snapshot.Settings.Targets.Any(target => target.Enabled)) return;
        var selected = new Dictionary<string, object?>(StringComparer.Ordinal);
        if (fields is not null)
        {
            foreach (var (name, value) in fields)
            {
                if (!SafeFields.Contains(name) || value is null || selected.Count >= 32) continue;
                if (value is string message)
                    selected[name] = Clean(message, 160);
                else if (value is bool or byte or short or int or long or uint or ulong or decimal)
                    selected[name] = value;
            }
        }
        var timestamp = fields?.GetValueOrDefault("occurredAtUtc") is DateTimeOffset occurred ? occurred : time.GetUtcNow();
        var record = new SyslogRecord(timestamp, Header(appName, 48), Header(eventCode, 32), severity, ids.NewId(), selected);
        var bytes = 256 + selected.Sum(item => Encoding.UTF8.GetByteCount(item.Key) + (item.Value is string value ? Encoding.UTF8.GetByteCount(value) : 32) + 24);
        // 为审计及故障保留一小部分入口空间。发送线程独占消费，生产者只尝试入队。
        var reserved = severity <= SyslogSeverity.Notice;
        var maxBytes = (reserved ? 16 : 15) * 1024 * 1024;
        var capacity = reserved ? snapshot.Settings.QueueCapacity : Math.Max(1, snapshot.Settings.QueueCapacity * 9 / 10);
        var count = Interlocked.Increment(ref _count);
        var size = Interlocked.Add(ref _bytes, bytes);
        if (count <= capacity && size <= maxBytes && _queue.Writer.TryWrite(new(snapshot, record, bytes))) return;
        Interlocked.Decrement(ref _count);
        Interlocked.Add(ref _bytes, -bytes);
        foreach (var target in snapshot.Settings.Targets.Where(target => target.Enabled)) RecordDrop(target.Id);
    }

    internal void RecordDrop(string targetId, long count = 1) => Dropped.AddOrUpdate(targetId, count, (_, previous) => previous + count);

    internal bool TryRead(out Pending? pending)
    {
        if (!_queue.Reader.TryRead(out pending)) return false;
        Interlocked.Decrement(ref _count);
        Interlocked.Add(ref _bytes, -pending.Bytes);
        return true;
    }

    private static string Clean(string text, int limit) => new(text.Take(limit).Select(value => char.IsControl(value) ? ' ' : value).ToArray());
    private static string Header(string text, int limit) => text.Length == 0 ? "-" :
        new(text.Take(limit).Select(value => value is >= '!' and <= '~' ? value : '-').ToArray());
}
