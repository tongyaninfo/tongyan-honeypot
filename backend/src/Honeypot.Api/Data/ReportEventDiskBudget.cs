using System.Data.Common;
using System.Globalization;
using Honeypot.Api.Options;
using Honeypot.Api.Service.impl;
using Microsoft.EntityFrameworkCore;

namespace Honeypot.Api.Data;

public sealed class ReportEventDiskBudget(TimeProvider time)
{
    private const long MiB = 1024 * 1024;
    private const long MinimumJournalHeadroom = MiB;
    private readonly object _diskGate = new();
    private string? _cachedPath;
    private long _checkedTimestamp;
    private long _cachedDatabaseBytes;
    private long? _cachedFreeBytes;

    internal async Task<bool> CanWriteAsync(HoneypotDbContext db, EventStorageOptions options,
        ReportIngestionHealth health, CancellationToken cancellationToken)
    {
        var connection = db.Database.GetDbConnection();
        var path = connection.DataSource;
        if (string.IsNullOrEmpty(path) || path == ":memory:") return true;

        path = Path.GetFullPath(path);
        var sidecarBytes = Length(path + "-wal") + Length(path + "-shm") + Length(path + "-journal");
        var totalBytes = Length(path) + sidecarBytes;
        health.RecordDatabaseBytes(totalBytes);

        // 为事务日志预留空间，限制采集连接的主库页数，达到上限时 SQLite 返回 SQLITE_FULL。
        var budget = (long)options.DatabaseBudgetMiB * MiB;
        var mainBudget = budget - MinimumJournalHeadroom - sidecarBytes;
        var requiredFree = options.MinimumFreeDiskMiB * MiB + MinimumJournalHeadroom;
        var freeBytes = CachedDiskFreeBytes(path, totalBytes);
        if (totalBytes >= budget || mainBudget <= 0 || freeBytes is null || freeBytes < requiredFree)
        {
            health.SetDiskBudgetBlocked(true);
            return false;
        }

        var pageSize = Convert.ToInt64(await ExecutePragmaAsync(connection, "PRAGMA main.page_size", cancellationToken), CultureInfo.InvariantCulture);
        var maxPages = mainBudget / pageSize;
        if (maxPages < 1)
        {
            health.SetDiskBudgetBlocked(true);
            return false;
        }

        // PRAGMA 语法不支持绑定参数。这里仅使用本地整型配置和已测得的文件大小计算页数。
        var result = await ExecutePragmaAsync(connection, "PRAGMA main.max_page_count = " + maxPages.ToString(CultureInfo.InvariantCulture), cancellationToken);
        var effectivePages = Convert.ToInt64(result, CultureInfo.InvariantCulture);
        var allowed = effectivePages <= maxPages;
        // 周期检查不能覆写 SQLITE_FULL 状态，写入提交成功时再确认采集已恢复。
        if (!allowed) health.SetDiskBudgetBlocked(true);
        return allowed;
    }

    internal static async Task CheckpointAsync(HoneypotDbContext db, CancellationToken cancellationToken)
    {
        if (db.Database.GetDbConnection().DataSource is "" or ":memory:") return;
        // 回收空闲页用于后续写入，由 SQLite 自己截断 WAL；主文件不会在在线维护时执行 VACUUM。
        await ExecutePragmaAsync(db.Database.GetDbConnection(), "PRAGMA main.wal_checkpoint(TRUNCATE)", cancellationToken);
    }

    public static long? ReadDiskFreeBytes(string path)
    {
        try
        {
            path = Path.GetFullPath(path);
            var drive = DriveInfo.GetDrives().Where(drive =>
                path == drive.RootDirectory.FullName ||
                path.StartsWith(drive.RootDirectory.FullName.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar,
                    OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
                .OrderByDescending(drive => drive.RootDirectory.FullName.Length).FirstOrDefault();
            return drive is { IsReady: true } ? drive.AvailableFreeSpace : null;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or ArgumentException or System.Security.SecurityException)
        {
            return null;
        }
    }

    private long? CachedDiskFreeBytes(string path, long totalBytes)
    {
        lock (_diskGate)
        {
            var timestamp = time.GetTimestamp();
            if (_cachedPath == path && time.GetElapsedTime(_checkedTimestamp, timestamp) < TimeSpan.FromSeconds(2))
                return _cachedFreeBytes - Math.Max(0, totalBytes - _cachedDatabaseBytes);
            _cachedFreeBytes = ReadDiskFreeBytes(path);
            _cachedDatabaseBytes = totalBytes;
            _cachedPath = path;
            _checkedTimestamp = timestamp;
            return _cachedFreeBytes;
        }
    }

    private static long Length(string path)
    {
        try { return new FileInfo(path).Length; }
        catch (FileNotFoundException) { return 0; }
    }

    private static async Task<object?> ExecutePragmaAsync(DbConnection connection, string commandText, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandTimeout = 2;
        command.CommandText = commandText;
        return await command.ExecuteScalarAsync(cancellationToken);
    }
}
