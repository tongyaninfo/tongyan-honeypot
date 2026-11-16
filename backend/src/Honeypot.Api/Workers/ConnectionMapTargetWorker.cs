using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using Honeypot.Api.Common;
using Honeypot.Api.Models;
using Honeypot.Api.Options;
using Honeypot.Api.Service;
using Honeypot.Api.Service.impl;
using Honeypot.Shared.Models;
using Microsoft.Extensions.Primitives;

namespace Honeypot.Api.Workers;

internal sealed class ConnectionMapTargetWorker : BackgroundService, IConnectionMapTarget
{
    private const string CoordinatesSource = "configuredCoordinates";
    private const string ConfiguredIpSource = "configuredPublicIp";
    private const string DetectedIpSource = "detectedPublicIp";
    private static readonly TimeSpan CacheLifetime = TimeSpan.FromDays(1);
    private static readonly TimeSpan FailureBackoff = TimeSpan.FromMinutes(15);
    private static readonly TimeSpan WorkerInterval = TimeSpan.FromSeconds(1);
    private readonly IConfiguration _configuration;
    private readonly IIPLocationSettingsStore _locationSettings;
    private readonly IIPLocation _locations;
    private readonly ConnectionMapPublicIpProbe _probe;
    private readonly ConnectionMapTargetCache _cache;
    private readonly TimeProvider _clock;
    private readonly IDisposable _configurationSubscription;
    private readonly object _gate = new();
    private Generation _current;
    private bool _disposed;

    public ConnectionMapTargetWorker(IConfiguration configuration, IIPLocationSettingsStore locationSettings,
        IIPLocation locations, ConnectionMapPublicIpProbe probe, ConnectionMapTargetCache cache, TimeProvider clock)
    {
        _configuration = configuration;
        _locationSettings = locationSettings;
        _locations = locations;
        _probe = probe;
        _cache = cache;
        _clock = clock;
        _current = new(ReadSetup());
        _locationSettings.Changed += LocationSettingsChanged;
        _configurationSubscription = ChangeToken.OnChange(configuration.GetReloadToken, ResetOnChange);
        ResetOnChange();
    }

    public ConnectionMapTarget GetSnapshot()
    {
        lock (_gate)
        {
            // 配置回调到达前也按当前目标判定，切换解析服务不会让同一落点闪退。
            var setup = ReadSetup();
            var snapshot = _current.Setup == setup ? _current.Snapshot : RetainLastLocation(setup, _current);
            return snapshot with
            {
                Stale = snapshot.Stale || snapshot.UpdatedAtUtc is { } updatedAt && _clock.GetUtcNow() - updatedAt >= CacheLifetime,
            };
        }
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(WorkerInterval, _clock);
        do
        {
            var generation = Current();
            if (!generation.Setup.CanRefresh) continue;
            if (!generation.RestoreAttempted)
            {
                generation.RestoreAttempted = true;
                await RestoreAsync(generation, stoppingToken);
            }
            if (!generation.Token.IsCancellationRequested && _clock.GetUtcNow() >= generation.NextAttemptAtUtc)
                await RefreshAsync(generation, stoppingToken);
        } while (await timer.WaitForNextTickAsync(stoppingToken));
    }

    private async Task RestoreAsync(Generation generation, CancellationToken stoppingToken)
    {
        using var work = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken, generation.Token);
        try
        {
            var setup = generation.Setup;
            var cached = await _cache.ReadAsync(setup.Fingerprint(), setup.TargetFingerprint(), setup.Initial.Source!,
                allowLegacyFallback: setup.Initial.Source == DetectedIpSource, _clock.GetUtcNow(), work.Token);
            // 同一份结果已作为切换期间的回退，不能用磁盘副本取消本次刷新。
            if (cached is null || generation.Snapshot.UpdatedAtUtc >= cached.UpdatedAtUtc) return;

            var restored = cached with { Label = setup.Label ?? SafeLabel(cached.Label) ?? setup.Initial.Label };
            if (Publish(generation, restored) && !cached.Stale)
                generation.NextAttemptAtUtc = cached.UpdatedAtUtc!.Value.Add(CacheLifetime);
        }
        catch (OperationCanceledException) when (work.IsCancellationRequested) { }
    }

    private async Task RefreshAsync(Generation generation, CancellationToken stoppingToken)
    {
        using var work = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken, generation.Token);
        try
        {
            var setup = generation.Setup;
            var ip = setup.PublicIp ?? await _probe.DiscoverAsync(setup.Location, work.Token);
            // 每次续期都由当前所选库实际查询，避免列表命中旧坐标时误推进更新时间。
            var location = ip is null ? null : await _locations.ResolveAsync(ip, setup.Location, work.Token);
            var now = _clock.GetUtcNow();
            if (location is not { Status: "resolved" } ||
                !string.Equals(location.Source, setup.Location.Database, StringComparison.OrdinalIgnoreCase) ||
                !IPLocationAddress.HasCoordinates(location.Latitude, location.Longitude))
            {
                generation.NextAttemptAtUtc = now.Add(FailureBackoff);
                // 失败保留同一部署目标最近一次成功坐标，直到当前解析服务成功刷新。
                if (generation.Snapshot.Status != "ready") Publish(generation, setup.Initial with { Status = "unavailable" });
                return;
            }

            var result = setup.Initial with
            {
                Status = "ready", Latitude = location.Latitude, Longitude = location.Longitude, UpdatedAtUtc = now,
                Label = setup.Label ?? LocationLabel(location) ?? setup.Initial.Label,
            };
            generation.NextAttemptAtUtc = now.Add(CacheLifetime);
            if (Publish(generation, result))
                await _cache.WriteAsync(setup.Fingerprint(), setup.TargetFingerprint(), result, work.Token);
        }
        catch (OperationCanceledException) when (work.IsCancellationRequested) { }
    }

    private static string? SafeLabel(string? label) =>
        label is { Length: > 0 and <= 128 } && !label.Any(char.IsControl) && !IPLocationAddress.TryParse(label, out _) ? label : null;

    private static string? LocationLabel(IPLocationResult location)
    {
        // 只使用归属地字段，不把探测 IP 或提供方的整段描述用于展示。
        var parts = new[] { location.Country, location.Province, location.City }.Select(SafeLabel)
            .Where(part => part is not null).Distinct(StringComparer.Ordinal);
        return SafeLabel(string.Join(" · ", parts));
    }

    private bool Publish(Generation generation, ConnectionMapTarget snapshot)
    {
        lock (_gate)
        {
            if (_disposed || _current != generation || generation.Setup != ReadSetup()) return false;
            generation.Snapshot = snapshot;
            return true;
        }
    }

    private TargetSetup ReadSetup()
    {
        var target = ConnectionMapTargetOptions.Read(_configuration);
        var location = _locationSettings.Current;
        var configuredLabel = SafeLabel(target.Label);
        var label = configuredLabel ?? "蜜罐节点";
        if (target.Latitude is not null || target.Longitude is not null)
        {
            var latitude = ParseCoordinate(target.Latitude);
            var longitude = ParseCoordinate(target.Longitude);
            var initial = IPLocationAddress.HasCoordinates(latitude, longitude)
                ? new ConnectionMapTarget("ready", label, latitude, longitude, CoordinatesSource)
                : new ConnectionMapTarget("unavailable", label, Source: CoordinatesSource);
            return new(location, initial, null, configuredLabel);
        }

        var source = target.PublicIp is null ? DetectedIpSource : ConfiguredIpSource;
        string? ip = null;
        if (target.PublicIp is { } configuredIp)
        {
            if (IPLocationAddress.Classify(configuredIp, out var normalized) is not null)
                return new(location, new("unavailable", label, Source: source), null, configuredLabel);
            ip = normalized;
        }
        return new(location, new(location.Enabled ? "pending" : "disabled", label, Source: source), ip, configuredLabel);
    }

    private static double? ParseCoordinate(string? value) =>
        double.TryParse(value, NumberStyles.Float, CultureInfo.InvariantCulture, out var coordinate) ? coordinate : null;

    private Generation Current()
    {
        lock (_gate) return _current;
    }

    private void LocationSettingsChanged(IPLocationSettings _) => ResetOnChange();

    private static ConnectionMapTarget RetainLastLocation(TargetSetup setup, Generation previous)
    {
        if (!setup.CanRefresh || !previous.Setup.CanRefresh || setup.Initial.Source != previous.Setup.Initial.Source ||
            setup.PublicIp != previous.Setup.PublicIp || previous.Snapshot is not { Status: "ready", UpdatedAtUtc: not null } last)
            return setup.Initial;

        return last with { Label = setup.Label ?? SafeLabel(last.Label) ?? setup.Initial.Label, Stale = true };
    }

    private void ResetOnChange()
    {
        Generation previous;
        lock (_gate)
        {
            if (_disposed) return;
            var setup = ReadSetup();
            if (_current.Setup == setup) return;
            previous = _current;
            _current = new(setup, RetainLastLocation(setup, previous));
        }
        // 不在配置更新锁中等待网络，已经发出的旧查询不能提交到新配置。
        previous.Cancel();
    }

    public override void Dispose()
    {
        Generation previous;
        lock (_gate)
        {
            if (_disposed) return;
            _disposed = true;
            previous = _current;
        }
        _locationSettings.Changed -= LocationSettingsChanged;
        _configurationSubscription.Dispose();
        previous.Cancel();
        base.Dispose();
    }

    private sealed record TargetSetup(IPLocationSettings Location, ConnectionMapTarget Initial, string? PublicIp, string? Label)
    {
        public bool CanRefresh => Initial.Status == "pending";

        // 仅保存身份指纹，缓存正文不保存用户配置或探测到的公网 IP。
        public string Fingerprint() => Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(this)));

        public string TargetFingerprint() =>
            Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(new { Initial.Source, PublicIp })));
    }

    private sealed class Generation
    {
        private readonly CancellationTokenSource _stop = new();
        public TargetSetup Setup { get; }
        public ConnectionMapTarget Snapshot { get; set; }
        public DateTimeOffset NextAttemptAtUtc { get; set; }
        public bool RestoreAttempted { get; set; }
        public CancellationToken Token { get; }

        public Generation(TargetSetup setup, ConnectionMapTarget? snapshot = null)
        {
            Setup = setup;
            Snapshot = snapshot ?? setup.Initial;
            Token = _stop.Token;
        }

        public void Cancel()
        {
            _stop.Cancel();
            _stop.Dispose();
        }
    }
}
