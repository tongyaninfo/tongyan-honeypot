using System.Threading.Channels;
using Honeypot.Api.Common;
using Honeypot.Api.Options;
using Honeypot.Shared.Models;

namespace Honeypot.Api.Service.impl;

/// <summary>有界后台解析协调器。短锁仅保护内存，业务请求不等待外部 I/O。</summary>
public sealed class IPLocationResolver : IIPLocationResolver, IDisposable
{
    private sealed record WorkItem(string Ip, long Generation, IPLocationSettings Settings, CancellationToken Token);
    private sealed record CacheEntry(IPLocationResult Result, DateTimeOffset ExpiresAt, LinkedListNode<string> Node);
    private readonly object _sync = new();
    private readonly IIPLocationSettingsStore _store;
    private readonly IIPLocation _adapter;
    private readonly IPLocationOptions _options;
    private readonly TimeProvider _time;
    private readonly ISyslogPublisher? _logs;
    private readonly Channel<WorkItem> _queue;
    private readonly HashSet<string> _pending = new(StringComparer.Ordinal);
    private readonly Dictionary<string, CacheEntry> _cache = new(StringComparer.Ordinal);
    private readonly LinkedList<string> _cacheOrder = new();
    private IPLocationSettings _settings;
    private CancellationTokenSource _generationCancellation = new();
    private long _generation;
    private int _disposed;
    private int _failedResolutions;
    private int _busyRequests;
    private DateTimeOffset _nextBusyReport;

    public IPLocationResolver(IIPLocationSettingsStore store, IIPLocation adapter, IPLocationOptions options, TimeProvider time, ISyslogPublisher? logs = null)
    {
        if (options.QueueCapacity < 1 || options.CacheCapacity < 1 || options.Concurrency is < 1 or > 4)
            throw new ArgumentOutOfRangeException(nameof(options));
        _store = store;
        _adapter = adapter;
        _options = options;
        _time = time;
        _logs = logs;
        _settings = store.Current;
        _queue = Channel.CreateBounded<WorkItem>(new BoundedChannelOptions(options.QueueCapacity)
        {
            FullMode = BoundedChannelFullMode.Wait, SingleReader = false, SingleWriter = false,
            AllowSynchronousContinuations = false
        });
        store.Changed += ChangeSettings;
    }

    public IPLocationBatchResult Resolve(IReadOnlyList<string> ips)
    {
        lock (_sync)
        {
            var items = new List<IPLocationResult>(ips.Count);
            foreach (var input in ips.Distinct(StringComparer.Ordinal))
            {
                var local = IPLocationAddress.Classify(input, out var ip);
                if (local is not null) { items.Add(local); continue; }
                if (!_settings.Enabled) { items.Add(new(input, "disabled", "IP 解析未开启")); continue; }
                if (_cache.TryGetValue(ip, out var cached))
                {
                    if (cached.ExpiresAt > _time.GetUtcNow())
                    {
                        _cacheOrder.Remove(cached.Node);
                        _cacheOrder.AddLast(cached.Node);
                        items.Add(cached.Result with { Ip = input });
                        continue;
                    }
                    _cache.Remove(ip);
                    _cacheOrder.Remove(cached.Node);
                }
                if (_pending.Contains(ip)) { items.Add(new(input, "pending", "归属地解析中")); continue; }
                var work = new WorkItem(ip, _generation, _settings, _generationCancellation.Token);
                if (_queue.Writer.TryWrite(work))
                {
                    _pending.Add(ip);
                    items.Add(new(input, "pending", "归属地解析中"));
                }
                else
                {
                    items.Add(new(input, "busy", "解析队列繁忙"));
                    _busyRequests++;
                    var now = _time.GetUtcNow();
                    if (now >= _nextBusyReport)
                    {
                        _logs?.Publish("honeypot-iplocation", "IP_LOCATION_QUEUE_BUSY", SyslogSeverity.Warning,
                            new Dictionary<string, object?> { ["count"] = _busyRequests });
                        _busyRequests = 0;
                        _nextBusyReport = now.AddMinutes(1);
                    }
                }
            }
            return new(_settings.Enabled, items);
        }
    }

    public Task RunAsync(CancellationToken cancellationToken) => Task.WhenAll(
        Enumerable.Range(0, _options.Concurrency).Select(_ => ConsumeAsync(cancellationToken)));

    private async Task ConsumeAsync(CancellationToken cancellationToken)
    {
        try
        {
            await foreach (var work in _queue.Reader.ReadAllAsync(cancellationToken))
            {
                lock (_sync)
                {
                    if (work.Generation != _generation || !_settings.Enabled) continue;
                }
                IPLocationResult result;
                using var linked = CancellationTokenSource.CreateLinkedTokenSource(work.Token, cancellationToken);
                try { result = await _adapter.ResolveAsync(work.Ip, work.Settings, linked.Token).ConfigureAwait(false); }
                catch (OperationCanceledException) { result = new(work.Ip, "failed", "归属地解析失败"); }
                catch (Exception error)
                {
                    // 单个解析器故障必须隔离，不允许后台异常终止宿主或泄露上游正文。
                    _logs?.Publish("honeypot-iplocation", "IP_LOCATION_INTERNAL_FAILURE", SyslogSeverity.Error,
                        new Dictionary<string, object?> { ["exceptionType"] = error.GetType().Name });
                    result = new(work.Ip, "failed", "归属地解析失败");
                }
                lock (_sync)
                {
                    if (work.Generation != _generation || !_settings.Enabled || cancellationToken.IsCancellationRequested) continue;
                    _pending.Remove(work.Ip);
                    while (_cache.Count >= _options.CacheCapacity && _cacheOrder.First is { } first)
                    {
                        _cache.Remove(first.Value);
                        _cacheOrder.RemoveFirst();
                    }
                    var node = _cacheOrder.AddLast(work.Ip);
                    var lifetime = result.Status == "resolved" ? _options.SuccessLifetime : _options.FailureLifetime;
                    _cache[work.Ip] = new(result, _time.GetUtcNow() + lifetime, node);
                    LogResolution(result.Status);
                }
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }
    }

    private void LogResolution(string status)
    {
        if (status == "failed")
        {
            _failedResolutions++;
            if (_failedResolutions is 1 or 3 || _failedResolutions % 50 == 0)
                _logs?.Publish("honeypot-iplocation", "IP_LOCATION_FAILED",
                    _failedResolutions < 3 ? SyslogSeverity.Informational : SyslogSeverity.Warning,
                    new Dictionary<string, object?> { ["failureCount"] = _failedResolutions });
            return;
        }
        if (_failedResolutions >= 3)
            _logs?.Publish("honeypot-iplocation", "IP_LOCATION_RECOVERED", SyslogSeverity.Notice);
        _failedResolutions = 0;
        _logs?.Publish("honeypot-iplocation", "IP_LOCATION_COMPLETED", SyslogSeverity.Debug,
            new Dictionary<string, object?> { ["status"] = status });
    }

    private void ChangeSettings(IPLocationSettings settings)
    {
        CancellationTokenSource previous;
        lock (_sync)
        {
            if (_disposed != 0) return;
            _settings = settings;
            _generation++;
            previous = _generationCancellation;
            _generationCancellation = new();
            _pending.Clear();
            _cache.Clear();
            _cacheOrder.Clear();
            _failedResolutions = 0;
            _busyRequests = 0;
            while (_queue.Reader.TryRead(out _)) { }
        }
        previous.Cancel();
        previous.Dispose();
    }

    public void Dispose()
    {
        // 同一单例通过具体类型与接口注册，DI 释放两次时必须幂等。
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        _store.Changed -= ChangeSettings;
        _queue.Writer.TryComplete();
        _generationCancellation.Cancel();
        _generationCancellation.Dispose();
    }
}
