using System.Diagnostics;
using Honeypot.Api.Data;
using Honeypot.Api.Data.Models;
using Honeypot.Api.Options;
using Honeypot.Api.Service;
using Honeypot.Api.Service.impl;
using Honeypot.Protocol.Abstractions.Service;
using Honeypot.Shared.Models;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Honeypot.Api.Workers;

/// <summary>周期采集进程资源与监听运行态；不将停机、采样失败或重启之间的空白当成正常运行。</summary>
public sealed class ReportRuntimeSamplerWorker(
    IDbContextFactory<HoneypotDbContext> factory,
    IListenerHost listeners,
    IServiceInstanceStore instances,
    ReportIngestionHealth health,
    TimeProvider time,
    IConfiguration configuration,
    IHostEnvironment environment,
    ReportEventDiskBudget diskBudget,
    ILogger<ReportRuntimeSamplerWorker> logger,
    ISyslogPublisher? logs = null) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        long? previousSample = null;
        long lastFailureCount = 0;
        double? previousCpuMs = null;
        long? previousTimestamp = null;
        var consecutiveFailures = 0;
        string? previousDiskStatus = null;
        var directory = configuration["Honeypot:DataDirectory"];
        if (string.IsNullOrWhiteSpace(directory)) directory = Path.Combine(environment.ContentRootPath, "data");
        using var process = Process.GetCurrentProcess();
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(30), time);
        do
        {
            try
            {
                var now = time.GetUtcNow().ToUnixTimeMilliseconds();
                var timestamp = time.GetTimestamp();
                process.Refresh();
                var cpuMs = process.TotalProcessorTime.TotalMilliseconds;
                var elapsedMs = previousTimestamp is { } before ? time.GetElapsedTime(before, timestamp).TotalMilliseconds : 0;
                var failureCount = health.PersistenceFailures;
                var failures = Math.Max(0, failureCount - lastFailureCount);
                var statuses = listeners.GetStatuses();
                var expected = instances.GetAll().Where(item => item.DesiredState.Equals("Running", StringComparison.OrdinalIgnoreCase))
                    .SelectMany(item => item.Bindings).Where(item => item.Enabled).Select(item => item.ListenerId).ToHashSet(StringComparer.OrdinalIgnoreCase);
                var expectedStatuses = statuses.Where(item => expected.Contains(item.ListenerId)).ToArray();
                var sample = new ReportRuntimeSampleEntity
                {
                    CapturedAtUnixMs = now,
                    CoverageStartAtUnixMs = previousSample is { } previous && now > previous && now - previous <= 60_000 && failures == 0 ? previous : now,
                    ProcessCpuPercent = elapsedMs > 0 && previousCpuMs is { } cpu ? Math.Clamp(100d * (cpuMs - cpu) / elapsedMs / Environment.ProcessorCount, 0, 100) : null,
                    ProcessMemoryBytes = process.WorkingSet64,
                    DataDiskFreeBytes = diskBudget.SampleFreeBytes(directory, health),
                    ActiveConnections = statuses.Sum(item => (long)item.ActiveConnections),
                    // 仅期望运行的监听器计入正常采样分母，主动停止不算故障。
                    ConfiguredListeners = expected.Count,
                    RunningListeners = expectedStatuses.Count(item => item.State.Equals("Running", StringComparison.OrdinalIgnoreCase)),
                    FailedListeners = expectedStatuses.Count(item => item.State.Equals("Failed", StringComparison.OrdinalIgnoreCase)),
                    PersistenceFailures = failures,
                };
                // 低水位与探测不可用仅触发告警，绝不能在 SQLite 返回前推断写入失败。
                var diskStatus = health.DiskSpaceStatus;
                if (diskStatus != previousDiskStatus)
                {
                    if (diskStatus != "available")
                        logger.LogWarning("Data volume monitoring warning. Status={Status} FreeBytes={FreeBytes}", diskStatus, sample.DataDiskFreeBytes);
                    else if (previousDiskStatus is not null)
                        logger.LogInformation("Data volume monitoring recovered.");
                    previousDiskStatus = diskStatus;
                }
                await using var db = await factory.CreateDbContextAsync(stoppingToken);
                db.Database.SetCommandTimeout(2);
                await db.Database.OpenConnectionAsync(stoppingToken);
                diskBudget.Observe(db, health);
                db.Set<ReportRuntimeSampleEntity>().Add(sample);
                await db.SaveChangesAsync(stoppingToken);
                health.RecoverStage("sample.commit");
                if (consecutiveFailures >= 3)
                    logs?.Publish("honeypot-report", "REPORT_SAMPLING_RECOVERED", SyslogSeverity.Notice);
                consecutiveFailures = 0;
                previousSample = now;
                lastFailureCount = failureCount;
                previousCpuMs = cpuMs;
                previousTimestamp = timestamp;
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (Exception error)
            {
                previousSample = null;
                previousCpuMs = null;
                previousTimestamp = null;
                health.RecordFailure();
                health.RecordStageFault("sample.commit", ReportIngestionHealth.Classify(error));
                if ((error is DbUpdateException ? error.InnerException : error) is SqliteException { SqliteErrorCode: 13 })
                    health.SetDiskBudgetBlocked(true);
                consecutiveFailures++;
                if (consecutiveFailures == 1) logger.LogWarning("Report runtime sampling failed; the interval remains unknown.");
                if (consecutiveFailures == 3)
                    logger.LogError("Report runtime sampling has consecutive failures. FailureCount={FailureCount}", consecutiveFailures);
            }
        } while (await timer.WaitForNextTickAsync(stoppingToken));
    }

}
