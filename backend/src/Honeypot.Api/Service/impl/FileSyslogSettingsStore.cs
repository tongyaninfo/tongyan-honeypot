using System.Text.Json;
using System.Text.Json.Serialization;
using Honeypot.Api.Common;
using Honeypot.Shared.Models;

namespace Honeypot.Api.Service.impl;

/// <summary>配置保存先落盘再发布快照；初始化不依赖 Logger，避免日志 Provider 循环构造。</summary>
public sealed class FileSyslogSettingsStore : ISyslogSettingsStore
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    { WriteIndented = true, MaxDepth = 8, UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow };
    private readonly string _path;
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private SyslogSettingsSnapshot _current;
    public event Action<SyslogSettingsSnapshot>? Changed;
    public SyslogSettingsSnapshot Current => Copy(Volatile.Read(ref _current));
    SyslogSettingsSnapshot ISyslogSettingsStore.DeliverySnapshot => Volatile.Read(ref _current);

    public FileSyslogSettingsStore(IConfiguration configuration, IHostEnvironment environment)
    {
        var directory = configuration["Honeypot:DataDirectory"];
        if (string.IsNullOrWhiteSpace(directory)) directory = Path.Combine(environment.ContentRootPath, "data");
        _path = Path.Combine(directory, "syslog", "settings.json");
        var hostname = SyslogMessageFormatter.BuildHostname(Environment.MachineName);
        _current = new(new(), 0, hostname);
        if (!File.Exists(_path)) return;
        try
        {
            if (new FileInfo(_path).Length > 16384) throw new JsonException();
            var stored = JsonSerializer.Deserialize<StoredSettings>(File.ReadAllText(_path), JsonOptions);
            if (stored is null || stored.Revision < 0 || stored.Revision > 9007199254740990 ||
                !SyslogSettingsValidation.TryNormalize(stored.Settings, out var normalized)) throw new JsonException();
            _current = new(normalized, stored.Revision, hostname);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or JsonException or ArgumentException)
        {
            // 保留损坏原文件，关闭外发；不输出文件内容或异常正文。
            _current = new(new(), 0, hostname, "SYSLOG_CONFIGURATION_UNAVAILABLE");
        }
    }

    public async Task<SyslogSettingsSnapshot> SaveAsync(SyslogSettings settings, long expectedRevision, CancellationToken cancellationToken = default)
    {
        if (!SyslogSettingsValidation.TryNormalize(settings, out var normalized)) throw new ArgumentException("Syslog 配置无效。");
        await _writeLock.WaitAsync(cancellationToken);
        SyslogSettingsSnapshot saved;
        try
        {
            var current = Volatile.Read(ref _current);
            if (current.ConfigFault is not null) throw new SyslogSettingsUnavailableException();
            if (current.Revision != expectedRevision || current.Revision >= 9007199254740990) throw new SyslogSettingsConflictException();
            saved = new(normalized, current.Revision + 1, current.Hostname);
            Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
            var temporaryPath = _path + ".tmp";
            await File.WriteAllTextAsync(temporaryPath, JsonSerializer.Serialize(new StoredSettings(saved.Settings, saved.Revision), JsonOptions), cancellationToken);
            File.Move(temporaryPath, _path, true);
            Volatile.Write(ref _current, saved);
        }
        finally { _writeLock.Release(); }
        // 按版本消费快照；订阅方故障不能把已落盘保存伪装为失败。
        foreach (var handler in Changed?.GetInvocationList() ?? [])
        {
            try { ((Action<SyslogSettingsSnapshot>)handler)(Copy(saved)); }
            catch { /* 发送方还会读取 Current，旧任务不得阻止保存结果返回。 */ }
        }
        return Copy(saved);
    }

    private static SyslogSettingsSnapshot Copy(SyslogSettingsSnapshot value) => value with
    { Settings = value.Settings with { Targets = value.Settings.Targets.Select(target => target with { IgnoredSeverities = target.IgnoredSeverities?.ToArray() ?? [] }).ToArray() } };
    private sealed record StoredSettings(SyslogSettings Settings, long Revision);
}
