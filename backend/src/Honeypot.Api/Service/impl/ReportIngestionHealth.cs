using System.Collections.Concurrent;
using Honeypot.Api.Models;
using System.Diagnostics;
using System.Diagnostics.Metrics;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace Honeypot.Api.Service.impl;

/// <summary>每种错误只记录固定分类，异常正文与事件内容不进入指标。</summary>
public sealed class ReportIngestionHealth
{
    private static readonly Meter Meter = new("Honeypot.Storage");
    private static readonly Histogram<double> QueueWait = Meter.CreateHistogram<double>("honeypot.storage.queue_wait", "ms");
    private static readonly Histogram<double> WriteLock = Meter.CreateHistogram<double>("honeypot.storage.write_lock_wait", "ms");
    private static readonly Histogram<double> Commit = Meter.CreateHistogram<double>("honeypot.storage.commit", "ms");
    private static readonly Histogram<double> Append = Meter.CreateHistogram<double>("honeypot.storage.append", "ms");
    private readonly ConcurrentDictionary<string, long> _errors = new();
    private readonly ConcurrentDictionary<string, StorageFaultPeriod> _stages = new();
    private long _failures, _rejectedEvents, _databaseBytes, _lockRetries, _fileObservationFailures;
    private long _lastPersistedUnixMs = -1, _failureSinceUnixMs = -1, _lastRecoveredUnixMs = -1;
    private int _queueDepth, _diskBudgetBlocked, _retentionUnavailable;

    public long PersistenceFailures => Interlocked.Read(ref _failures);
    public long RejectedEvents => Interlocked.Read(ref _rejectedEvents);
    public long DatabaseBytes => Interlocked.Read(ref _databaseBytes);
    private long _freeDiskBytes = -1;
    public long? FreeDiskBytes => Interlocked.Read(ref _freeDiskBytes) is var bytes && bytes >= 0 ? bytes : null;
    public string DiskSpaceStatus => FreeDiskBytes switch { null => "unknown", < 256L * 1024 * 1024 => "low", _ => "available" };
    internal void RecordFreeDiskBytes(long? bytes) => Interlocked.Exchange(ref _freeDiskBytes, bytes ?? -1);
    public long FileObservationFailures => Interlocked.Read(ref _fileObservationFailures);
    internal void RecordFileObservationFailure() => Interlocked.Increment(ref _fileObservationFailures);
    public long LockRetries => Interlocked.Read(ref _lockRetries);
    public IReadOnlyDictionary<string, long> Errors => new Dictionary<string, long>(_errors);
    public IReadOnlyDictionary<string, StorageFaultPeriod> FaultsByStage => new Dictionary<string, StorageFaultPeriod>(_stages);
    public int EventQueueDepth => Math.Max(0, Volatile.Read(ref _queueDepth));
    public bool DiskBudgetBlocked => Volatile.Read(ref _diskBudgetBlocked) == 1;
    public bool RetentionAvailable => Volatile.Read(ref _retentionUnavailable) == 0;
    public DateTimeOffset? LastPersistedAtUtc => ReadUtc(ref _lastPersistedUnixMs);
    public DateTimeOffset? FailureSinceUtc => ReadUtc(ref _failureSinceUnixMs);
    public DateTimeOffset? LastRecoveredAtUtc => ReadUtc(ref _lastRecoveredUnixMs);

    private static DateTimeOffset? ReadUtc(ref long field) =>
        Interlocked.Read(ref field) is var ms && ms >= 0 ? DateTimeOffset.FromUnixTimeMilliseconds(ms) : null;

    internal static string Classify(Exception error) =>
        (error is DbUpdateException ? error.InnerException : error) is SqliteException sqlite
            ? sqlite.SqliteErrorCode switch
            {
                5 => "SQLITE_BUSY", 6 => "SQLITE_LOCKED", 8 => "SQLITE_READONLY",
                10 => "SQLITE_IOERR", 13 => "SQLITE_FULL", 14 => "SQLITE_CANTOPEN", _ => "REPORT_PERSISTENCE_FAILED",
            }
            : "REPORT_PERSISTENCE_FAILED";

    public void RecordFailure() => Interlocked.Increment(ref _failures);
    internal void RecordRejectedEvent(string code, string stage = "event.commit")
    {
        RecordStageFault(stage, code);
        Interlocked.CompareExchange(ref _failureSinceUnixMs, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(), -1);
        Interlocked.Increment(ref _rejectedEvents);
        RecordFailure();
    }

    internal void RecordStageFault(string stage, string code)
    {
        var now = DateTimeOffset.UtcNow;
        _errors.AddOrUpdate(code, 1, (_, n) => n + 1);
        _stages.AddOrUpdate(stage, _ => new(1, code, now, now, null),
            (_, last) => new(last.Occurrences + 1, code, last.SinceUtc ?? now, now, last.LastRecoveredAtUtc));
    }

    internal void RecoverStage(string stage)
    {
        while (_stages.TryGetValue(stage, out var last) && last.SinceUtc is not null)
            if (_stages.TryUpdate(stage, last with { SinceUtc = null, LastRecoveredAtUtc = DateTimeOffset.UtcNow }, last)) break;
    }

    internal void RecordLockRetry() => Interlocked.Increment(ref _lockRetries);
    internal static void RecordQueue(long start) => QueueWait.Record(Stopwatch.GetElapsedTime(start).TotalMilliseconds);
    internal static void RecordWriteLock(long start) => WriteLock.Record(Stopwatch.GetElapsedTime(start).TotalMilliseconds);
    internal static void RecordCommit(long start) => Commit.Record(Stopwatch.GetElapsedTime(start).TotalMilliseconds);
    internal static void RecordAppend(long start) => Append.Record(Stopwatch.GetElapsedTime(start).TotalMilliseconds);
    internal void ChangeQueueDepth(int delta) => Interlocked.Add(ref _queueDepth, delta);
    internal void RecordPersisted(DateTimeOffset now)
    {
        Interlocked.Exchange(ref _lastPersistedUnixMs, now.ToUnixTimeMilliseconds());
        if (Interlocked.Exchange(ref _failureSinceUnixMs, -1) >= 0)
            Interlocked.Exchange(ref _lastRecoveredUnixMs, now.ToUnixTimeMilliseconds());
    }

    internal void RecordDatabaseBytes(long bytes) => Interlocked.Exchange(ref _databaseBytes, bytes);
    internal void SetDiskBudgetBlocked(bool blocked) => Volatile.Write(ref _diskBudgetBlocked, blocked ? 1 : 0);
    internal void SetRetentionAvailable(bool available) => Volatile.Write(ref _retentionUnavailable, available ? 0 : 1);
}
