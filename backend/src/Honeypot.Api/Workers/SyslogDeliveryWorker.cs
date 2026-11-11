using System.Collections.Concurrent;
using System.Globalization;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Text;
using Honeypot.Api.Common;
using Honeypot.Api.Service;
using Honeypot.Api.Service.impl;
using Honeypot.Shared.Models;

namespace Honeypot.Api.Workers;

public sealed class SyslogDeliveryWorker(
    ISyslogSettingsStore settings,
    SyslogQueue queue,
    IResourceIdGenerator ids,
    TimeProvider time,
    IConfiguration configuration,
    IHostEnvironment environment,
    ILogger<SyslogDeliveryWorker> logger) : BackgroundService, ISyslogDeliveryService
{
    internal const string LoggerCategory = "Honeypot.Api.Workers.SyslogDeliveryWorker";
    private readonly ConcurrentDictionary<string, SyslogTargetStatus> _status = new(StringComparer.Ordinal);
    private readonly SemaphoreSlim _tests = new(1);
    private SyslogSpool? _spool;
    private DateTimeOffset _nextTest;
    private long _nextSpoolDiagnostic;
    private long _discardedPaused;

    public SyslogDeliveryStatus GetStatus()
    {
        var current = settings.DeliverySnapshot;
        var enabled = current.Settings.Enabled;
        var targets = current.Settings.Targets.Select(target =>
        {
            var key = Key(target);
            var status = _status.GetValueOrDefault(key) ?? new(target.Id, "Waiting", 0, 0, 0, 0, 0, 0, 0);
            if (_spool is null && enabled && Volatile.Read(ref _nextSpoolDiagnostic) != 0)
                status = status with { State = "BackingOff", LastErrorCode = "SYSLOG_SPOOL_UNAVAILABLE" };
            return status with
            {
                State = enabled && target.Enabled ? status.State : "Disabled",
                PendingCount = _spool?.Count(key) ?? 0,
                DroppedCount = queue.Dropped.GetValueOrDefault(target.Id),
            };
        }).ToArray();
        var active = current.Settings.Targets.Where(target => enabled && target.Enabled).Select(Key).ToHashSet(StringComparer.Ordinal);
        return new(enabled, current.Hostname, targets, current.ConfigFault, _spool?.CountPaused(active) ?? 0, Volatile.Read(ref _discardedPaused));
    }

    public async Task<SyslogTestResult> TestAsync(string targetId, string? message = null, CancellationToken cancellationToken = default)
    {
        var snapshot = settings.DeliverySnapshot;
        var target = snapshot.Settings.Targets.FirstOrDefault(value => value.Id == targetId);
        var id = ids.NewId();
        if (target is null) return new(targetId, id, false, "Failed", "SYSLOG_TARGET_NOT_FOUND", time.GetUtcNow());
        if (!await _tests.WaitAsync(0, cancellationToken))
            return new(targetId, id, false, "Failed", "SYSLOG_TEST_RATE_LIMITED", time.GetUtcNow());
        try
        {
            var now = time.GetUtcNow();
            if (now < _nextTest) return new(targetId, id, false, "Failed", "SYSLOG_TEST_RATE_LIMITED", now);
            var record = new SyslogRecord(now, "honeypot-syslog", "SYSLOG_TEST", SyslogSeverity.Notice, id,
                new Dictionary<string, object?>
                {
                    ["correlationId"] = id,
                    ["message"] = string.IsNullOrWhiteSpace(message) ? "通研蜜罐 Syslog 测试消息" : message
                });
            var bytes = Format(record, snapshot, target);
            // 测试正文必须完整送出，超过报文预算时提示缩短，不发送被截断的测试包。
            if (bytes.AsSpan().IndexOf("\"truncated\":true"u8) >= 0)
                return new(targetId, id, false, "Failed", "SYSLOG_TEST_MESSAGE_TOO_LONG", now);
            _nextTest = now.AddSeconds(3);
            await using var transport = CreateTransport(target, snapshot.Settings);
            var result = await SendAsync(transport, bytes, snapshot.Settings, cancellationToken);
            var stage = result.Stage switch
            {
                SyslogDeliveryStage.LocalSubmitted => "LocalSubmitted",
                SyslogDeliveryStage.RelpAcknowledged => "Acknowledged",
                _ => "Written"
            };
            return new(targetId, id, true, stage, null, time.GetUtcNow());
        }
        catch (Exception error) when (IsTransportError(error) || error is OperationCanceledException && !cancellationToken.IsCancellationRequested)
        {
            return new(targetId, id, false, "Failed", ErrorCode(error), time.GetUtcNow());
        }
        finally { _tests.Release(); }
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        SyslogSettingsSnapshot? applied = null;
        CancellationTokenSource? generation = null;
        Task[] senders = [];
        var nextExpiry = DateTimeOffset.MinValue;
        using var timer = new PeriodicTimer(TimeSpan.FromMilliseconds(75));
        try
        {
            if (settings.DeliverySnapshot.ConfigFault is not null)
                logger.LogError("Syslog 配置无法读取，已暂停转发。");
            do
            {
                var current = settings.DeliverySnapshot;
                if (_spool is null && (current.Settings.Enabled || applied is null && File.Exists(SpoolPath())) &&
                    time.GetUtcNow().UtcTicks >= Volatile.Read(ref _nextSpoolDiagnostic))
                {
                    try { _spool = new SyslogSpool(SpoolPath()); }
                    catch (Exception error) when (IsStorageError(error)) { ReportStorageFailure(); }
                }
                if (applied?.Revision != current.Revision || (_spool is not null && current.Settings.Enabled && senders.Length == 0))
                {
                    if (generation is not null)
                    {
                        await generation.CancelAsync();
                        await Task.WhenAll(senders);
                        generation.Dispose();
                    }
                    var keys = current.Settings.Targets.Select(Key).ToHashSet(StringComparer.Ordinal);
                    foreach (var key in _status.Keys)
                        if (!keys.Contains(key)) _status.TryRemove(key, out _);
                    applied = current;
                    generation = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
                    senders = current.Settings.Enabled && _spool is { } spool
                        ? current.Settings.Targets.Where(target => target.Enabled)
                            .Select(target => SendTargetAsync(target, current, spool, generation.Token)).ToArray()
                        : [];
                }

                if (_spool is not null) PersistPending(512);
                if (_spool is not null && time.GetUtcNow() >= nextExpiry)
                {
                    nextExpiry = time.GetUtcNow().AddSeconds(15);
                    try
                    {
                        var expired = _spool.Expire(time.GetUtcNow().ToUnixTimeSeconds());
                        var activeTargets = ActiveTargets(current);
                        foreach (var (key, count) in expired)
                        {
                            if (activeTargets.TryGetValue(key, out var target)) queue.RecordDrop(target.Id, count);
                            else Interlocked.Add(ref _discardedPaused, count);
                        }
                    }
                    catch (Exception error) when (IsStorageError(error)) { ReportStorageFailure(); }
                }
            } while (await timer.WaitForNextTickAsync(stoppingToken));
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
        finally
        {
            if (generation is not null)
            {
                await generation.CancelAsync();
                await Task.WhenAll(senders);
                generation.Dispose();
            }
            // 退出时短时间内把内存中的已接受日志交给暂存，下次启动恢复。
            var deadline = time.GetUtcNow().AddSeconds(2);
            while (time.GetUtcNow() < deadline && PersistPending(128) == 128) { }
            Interlocked.Exchange(ref _spool, null)?.Dispose();
        }
    }

    private int PersistPending(int limit)
    {
        var count = 0;
        var active = ActiveTargets(settings.DeliverySnapshot);
        while (count < limit && queue.TryRead(out var item) && item is not null)
        {
            count++;
            foreach (var target in item.Snapshot.Settings.Targets.Where(target => target.Enabled))
            {
                try
                {
                    var bytes = Format(item.Record, item.Snapshot, target);
                    var key = Key(target);
                    var expiry = item.Record.Timestamp.AddHours(item.Snapshot.Settings.RetentionHours).ToUnixTimeSeconds();
                    if (_spool is null)
                    {
                        queue.RecordDrop(target.Id);
                        continue;
                    }
                    if (!_spool.TryAppend(key, bytes, item.Record.Severity, expiry, item.Snapshot.Settings.SpoolMaxBytes, active, out var evictedKey))
                        queue.RecordDrop(target.Id);
                    if (evictedKey is not null)
                    {
                        if (active.TryGetValue(evictedKey, out var evictedTarget)) queue.RecordDrop(evictedTarget.Id);
                        else Interlocked.Increment(ref _discardedPaused);
                    }
                    if (bytes.AsSpan().IndexOf("\"truncated\":true"u8) >= 0)
                        Update(target, key, status => status with { TruncatedCount = status.TruncatedCount + 1 });
                }
                catch (Exception error) when (IsStorageError(error) || error is ArgumentException)
                {
                    queue.RecordDrop(target.Id);
                    ReportStorageFailure();
                }
            }
        }
        return count;
    }

    private async Task SendTargetAsync(SyslogTarget target, SyslogSettingsSnapshot snapshot, SyslogSpool spool, CancellationToken token)
    {
        var key = Key(target);
        ISyslogTransport? transport = null;
        var failures = 0;
        try
        {
            while (!token.IsCancellationRequested && snapshot.Revision == settings.DeliverySnapshot.Revision)
            {
                SyslogSpool.Entry? pending = null;
                var sent = false;
                try
                {
                    var entry = spool.Acquire(key, time.GetUtcNow().ToUnixTimeSeconds(), out var dropped);
                    if (dropped != 0) queue.RecordDrop(target.Id, dropped);
                    if (entry is null)
                    {
                        await Task.Delay(100, token);
                        continue;
                    }
                    pending = entry.Value.Entry;
                    transport ??= CreateTransport(target, snapshot.Settings);
                    if (failures == 0)
                        Update(target, key, status => status with { State = status.SentCount == 0 ? "Connecting" : status.State });
                    else
                        Update(target, key, status => status with { RetriedCount = status.RetriedCount + 1 });
                    var result = await SendAsync(transport, entry.Value.Bytes, snapshot.Settings, token);
                    sent = true;
                    var confirmed = result.Stage == SyslogDeliveryStage.RelpAcknowledged;
                    var now = time.GetUtcNow();
                    Update(target, key, status => status with
                    {
                        State = result.Stage == SyslogDeliveryStage.LocalSubmitted ? "LocalSubmitted" : "Available",
                        SentCount = status.SentCount + 1,
                        ConfirmedCount = status.ConfirmedCount + (confirmed ? 1 : 0),
                        LastSentAtUtc = now,
                        LastConfirmedAtUtc = confirmed ? now : status.LastConfirmedAtUtc,
                        LastErrorCode = null
                    });
                    if (failures > 0)
                        queue.Publish("honeypot-syslog", "SYSLOG_TARGET_RECOVERED", SyslogSeverity.Notice,
                            new Dictionary<string, object?> { ["targetId"] = target.Id, ["failureCount"] = failures });
                    failures = 0;
                }
                catch (OperationCanceledException) when (token.IsCancellationRequested) { break; }
                catch (Exception error) when (IsTransportError(error) || IsStorageError(error) || error is OperationCanceledException)
                {
                    failures = Math.Min(failures + 1, 30);
                    var code = ErrorCode(error);
                    Update(target, key, status => status with
                    {
                        State = "BackingOff", FailedCount = status.FailedCount + 1, LastErrorCode = code
                    });
                    if (failures is 1 or 5)
                        logger.LogWarning("Syslog 目标 {TargetId} 投递暂不可用，代码 {Code}。", target.Id, code);
                    if (transport is not null)
                    {
                        await transport.DisposeAsync();
                        transport = null;
                    }
                }
                finally
                {
                    if (pending is not null)
                    {
                        try { spool.Complete(pending, sent); }
                        catch (Exception error) when (IsStorageError(error)) { ReportStorageFailure(); }
                    }
                }
                if (failures > 0)
                    await Task.Delay(TimeSpan.FromSeconds(Math.Min(60, 1 << Math.Min(failures - 1, 6))), token);
            }
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { }
        finally { if (transport is not null) await transport.DisposeAsync(); }
    }

    private static ISyslogTransport CreateTransport(SyslogTarget target, SyslogSettings options) =>
        new SyslogTransport(target, TimeSpan.FromSeconds(Math.Max(options.ConnectTimeoutSeconds, options.WriteTimeoutSeconds)));

    private static async Task<SyslogSendResult> SendAsync(ISyslogTransport transport, byte[] bytes, SyslogSettings options, CancellationToken token)
    {
        using var connect = CancellationTokenSource.CreateLinkedTokenSource(token);
        connect.CancelAfter(TimeSpan.FromSeconds(options.ConnectTimeoutSeconds));
        await transport.ConnectAsync(connect.Token);
        using var write = CancellationTokenSource.CreateLinkedTokenSource(token);
        write.CancelAfter(TimeSpan.FromSeconds(options.WriteTimeoutSeconds));
        return await transport.SendAsync(bytes, write.Token);
    }

    private static byte[] Format(SyslogRecord record, SyslogSettingsSnapshot snapshot, SyslogTarget target) =>
        SyslogMessageFormatter.Format(record, SyslogTarget.DefaultFacility, target.Protocol == SyslogProtocol.Udp ? 1200 : 8192, snapshot.Hostname);

    private void Update(SyslogTarget target, string key, Func<SyslogTargetStatus, SyslogTargetStatus> update) =>
        _status.AddOrUpdate(key, _ => update(new(target.Id, "Waiting", 0, 0, 0, 0, 0, 0, 0)), (_, old) => update(old));

    private void ReportStorageFailure()
    {
        var now = time.GetUtcNow();
        var previous = Volatile.Read(ref _nextSpoolDiagnostic);
        if (now.UtcTicks < previous || Interlocked.CompareExchange(ref _nextSpoolDiagnostic, now.AddSeconds(15).UtcTicks, previous) != previous) return;
        logger.LogError("Syslog 本地暂存暂不可用，请检查数据目录权限和磁盘空间。");
    }

    private string SpoolPath()
    {
        var root = configuration["Honeypot:DataDirectory"];
        if (string.IsNullOrWhiteSpace(root)) root = Path.Combine(environment.ContentRootPath, "data");
        return Path.Combine(root, "syslog", "queue-v1.bin");
    }

    private static string Key(SyslogTarget target) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(
        // 保留 local0 的旧目标指纹，升级后可继续发送该目标已有的暂存日志。
        FormattableString.Invariant($"{target.Id}|{target.Host.ToUpperInvariant()}|{target.Port}|{target.Protocol}|{target.IgnoreSslErrors}|{SyslogTarget.DefaultFacility}"))));

    private static Dictionary<string, SyslogTarget> ActiveTargets(SyslogSettingsSnapshot snapshot) => snapshot.Settings.Targets
        .Where(target => snapshot.Settings.Enabled && target.Enabled).ToDictionary(Key, StringComparer.Ordinal);

    private static bool IsStorageError(Exception error) => error is IOException or UnauthorizedAccessException or OverflowException;
    private static bool IsTransportError(Exception error) => error is IOException or AuthenticationException or SocketException or TimeoutException;
    private static string ErrorCode(Exception error) => error switch
    {
        AuthenticationException => "SYSLOG_CERTIFICATE_OR_TLS_REJECTED",
        TimeoutException or OperationCanceledException => "SYSLOG_TIMEOUT",
        SocketException => "SYSLOG_CONNECTION_FAILED",
        UnauthorizedAccessException => "SYSLOG_SPOOL_ACCESS_DENIED",
        _ => "SYSLOG_TRANSPORT_FAILED",
    };
}
