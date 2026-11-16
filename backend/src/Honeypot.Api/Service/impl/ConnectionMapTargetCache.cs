using System.Text.Json;
using Honeypot.Api.Common;
using Honeypot.Api.Models;

namespace Honeypot.Api.Service.impl;

/// <summary>用本机独立缓存保存最近一次成功的目标坐标，读写仅由后台任务发起。</summary>
internal sealed class ConnectionMapTargetCache(
    IConfiguration configuration, IHostEnvironment environment, ILogger<ConnectionMapTargetCache> logger)
{
    private const int MaximumBytes = 4096;
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { MaxDepth = 8 };
    private readonly string _path = Path.Combine(
        configuration["Honeypot:DataDirectory"] is { } directory && !string.IsNullOrWhiteSpace(directory)
            ? directory
            : Path.Combine(environment.ContentRootPath, "data"),
        "connection-map-target-cache.json");

    private sealed record CacheEntry(int SchemaVersion, string Fingerprint, ConnectionMapTarget Target, string? TargetFingerprint = null);

    public async Task<ConnectionMapTarget?> ReadAsync(string fingerprint, string targetFingerprint, string source,
        bool allowLegacyFallback, DateTimeOffset now, CancellationToken cancellationToken)
    {
        try
        {
            await using var input = new FileStream(_path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete,
                1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
            var bytes = new byte[MaximumBytes + 1];
            var count = await input.ReadAtLeastAsync(bytes, bytes.Length, false, cancellationToken);
            if (count > MaximumBytes) return null;
            var entry = JsonSerializer.Deserialize<CacheEntry>(bytes.AsSpan(0, count), Json);
            if (entry is not { SchemaVersion: 1, Target: { Status: "ready", UpdatedAtUtc: { } updatedAt } target } ||
                string.IsNullOrWhiteSpace(entry.Fingerprint) || target.Source != source || updatedAt > now ||
                !IPLocationAddress.HasCoordinates(target.Latitude, target.Longitude))
                return null;

            var sameConfiguration = entry.Fingerprint == fingerprint;
            // 旧文件只有查库配置指纹。只有同一数据目录的自动探测结果可以跨定位服务恢复，
            // 旧文件无法证明手工填写的公网 IP 是否仍然相同。
            var sameTarget = entry.TargetFingerprint is { } savedTarget
                ? savedTarget == targetFingerprint
                : sameConfiguration || allowLegacyFallback;
            if (!sameTarget) return null;

            return target with { UpdatedAtUtc = updatedAt.ToUniversalTime(), Stale = !sameConfiguration };
        }
        catch (IOException error) when (error is FileNotFoundException or DirectoryNotFoundException) { return null; }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or JsonException)
        {
            logger.LogWarning("地图目标位置缓存读取失败，将重新查询。");
            return null;
        }
    }

    public async Task WriteAsync(string fingerprint, string targetFingerprint, ConnectionMapTarget target, CancellationToken cancellationToken)
    {
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            var bytes = JsonSerializer.SerializeToUtf8Bytes(new CacheEntry(1, fingerprint, target, targetFingerprint), Json);
            if (bytes.Length > MaximumBytes) return;
            if (Path.GetDirectoryName(_path) is { Length: > 0 } directory) Directory.CreateDirectory(directory);
            var pending = _path + ".pending";
            var options = new FileStreamOptions
            {
                Mode = FileMode.Create, Access = FileAccess.Write, Share = FileShare.None,
                Options = FileOptions.Asynchronous | FileOptions.WriteThrough,
            };
            if (!OperatingSystem.IsWindows()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
            // 固定临时文件写完再替换，失败保留上一份完整缓存。
            await using (var output = new FileStream(pending, options))
            {
                await output.WriteAsync(bytes, cancellationToken);
                await output.FlushAsync(cancellationToken);
            }
            cancellationToken.ThrowIfCancellationRequested();
            File.Move(pending, _path, overwrite: true);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            logger.LogWarning("地图目标位置缓存写入失败，继续使用内存结果。");
        }
    }
}
