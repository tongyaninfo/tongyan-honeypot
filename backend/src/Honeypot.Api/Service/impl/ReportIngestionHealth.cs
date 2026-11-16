namespace Honeypot.Api.Service.impl;

/// <summary>记录当前进程的事件持久化故障，下一次心跳将增量写入报告采样。</summary>
public sealed class ReportIngestionHealth
{
    private long _failures;
    private long _rejectedEvents;
    private long _databaseBytes;
    private long _lastPersistedUnixMs = -1;
    private int _queueDepth;
    private int _diskBudgetBlocked;
    private int _retentionUnavailable;

    public long PersistenceFailures => Interlocked.Read(ref _failures);
    public long RejectedEvents => Interlocked.Read(ref _rejectedEvents);
    public long DatabaseBytes => Interlocked.Read(ref _databaseBytes);
    public int EventQueueDepth => Math.Max(0, Volatile.Read(ref _queueDepth));
    public bool DiskBudgetBlocked => Volatile.Read(ref _diskBudgetBlocked) == 1;
    public bool RetentionAvailable => Volatile.Read(ref _retentionUnavailable) == 0;
    public DateTimeOffset? LastPersistedAtUtc => Interlocked.Read(ref _lastPersistedUnixMs) is var timestamp && timestamp >= 0
        ? DateTimeOffset.FromUnixTimeMilliseconds(timestamp) : null;

    public void RecordFailure() => Interlocked.Increment(ref _failures);

    internal void RecordRejectedEvent()
    {
        Interlocked.Increment(ref _rejectedEvents);
        RecordFailure();
    }

    internal void ChangeQueueDepth(int delta) => Interlocked.Add(ref _queueDepth, delta);
    internal void RecordPersisted(DateTimeOffset now) => Interlocked.Exchange(ref _lastPersistedUnixMs, now.ToUnixTimeMilliseconds());
    internal void RecordDatabaseBytes(long bytes) => Interlocked.Exchange(ref _databaseBytes, bytes);
    internal void SetDiskBudgetBlocked(bool blocked) => Volatile.Write(ref _diskBudgetBlocked, blocked ? 1 : 0);
    internal void SetRetentionAvailable(bool available) => Volatile.Write(ref _retentionUnavailable, available ? 0 : 1);
}
