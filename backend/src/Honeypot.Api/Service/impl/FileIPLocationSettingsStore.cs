using System.Text.Json;
using Honeypot.Api.Common;
using Honeypot.Shared.Models;

namespace Honeypot.Api.Service.impl;

/// <summary>独立非敏感 JSON 配置，复用数据目录且不变更数据库结构。</summary>
public sealed class FileIPLocationSettingsStore : IIPLocationSettingsStore
{
    private readonly string _path;
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private readonly JsonSerializerOptions _jsonOptions = new(JsonSerializerDefaults.Web) { WriteIndented = true };
    private IPLocationSettings _current;
    public IPLocationSettings Current => Volatile.Read(ref _current);
    public event Action<IPLocationSettings>? Changed;

    public FileIPLocationSettingsStore(IConfiguration configuration, IHostEnvironment environment, ILogger<FileIPLocationSettingsStore> logger)
    {
        var directory = configuration["Honeypot:DataDirectory"];
        if (string.IsNullOrWhiteSpace(directory)) directory = Path.Combine(environment.ContentRootPath, "data");
        _path = Path.Combine(directory, "ip-location-settings.json");
        _current = new();
        if (!File.Exists(_path)) return;
        try
        {
            if (new FileInfo(_path).Length > 4096) throw new JsonException();
            var saved = JsonSerializer.Deserialize<IPLocationSettings>(File.ReadAllText(_path), _jsonOptions);
            if (saved is null || !IPLocationSettingsValidation.TryNormalize(saved, out var valid)) throw new JsonException();
            _current = valid;
        }
        catch (Exception error) when (error is JsonException or IOException or UnauthorizedAccessException)
        {
            // 损坏配置不启用外发，不在日志输出配置正文或异常中的文件内容。
            logger.LogWarning("IP 归属地配置读取失败，已使用默认关闭配置。请重新保存 IP 数据库配置。");
        }
    }

    public async Task SaveAsync(IPLocationSettings settings, CancellationToken cancellationToken)
    {
        if (!IPLocationSettingsValidation.TryNormalize(settings, out var normalized)) throw new ArgumentException("IP 配置无效。", nameof(settings));
        await _writeLock.WaitAsync(cancellationToken);
        try
        {
            var changed = Current != normalized;
            Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
            var temporaryPath = $"{_path}.tmp";
            await File.WriteAllTextAsync(temporaryPath, JsonSerializer.Serialize(normalized, _jsonOptions), cancellationToken);
            File.Move(temporaryPath, _path, true);
            Volatile.Write(ref _current, normalized);
            // 同值保存也重写文件，使首次保存与损坏配置恢复真正持久化；仅变更值才失效缓存。
            if (changed) Changed?.Invoke(normalized);
        }
        finally { _writeLock.Release(); }
    }
}
