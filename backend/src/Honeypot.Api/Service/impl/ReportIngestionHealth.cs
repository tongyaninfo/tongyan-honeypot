namespace Honeypot.Api.Service.impl;

/// <summary>记录当前进程的事件持久化故障，下一次心跳将增量写入报告采样。</summary>
public sealed class ReportIngestionHealth
{
    private long _failures;
    public long PersistenceFailures => Interlocked.Read(ref _failures);
    public void RecordFailure() => Interlocked.Increment(ref _failures);
}
