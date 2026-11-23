using Honeypot.Api.Service.impl;
using Microsoft.EntityFrameworkCore;

namespace Honeypot.Api.Data;

public sealed class ReportEventDiskBudget(Func<string, long>? readFileBytes = null, Func<string, long?>? readFreeBytes = null)
{
    private readonly Func<string, long> _fileBytes = readFileBytes ?? Length;

    /// <summary>低水位只影响监控状态；探测异常时继续提交事务。</summary>
    public long? SampleFreeBytes(string path, ReportIngestionHealth health)
    {
        long? bytes = null;
        try { bytes = (readFreeBytes ?? ReadDiskFreeBytes)(path); }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException) { }
        health.RecordFreeDiskBytes(bytes);
        return bytes;
    }

    // 容量仅用于观测。状态读取失败不改变数据库的实际提交结果。
    internal void Observe(HoneypotDbContext db, ReportIngestionHealth health)
    {
        try
        {
            var path = db.Database.GetDbConnection().DataSource;
            if (string.IsNullOrEmpty(path) || path == ":memory:") return;
            health.RecordDatabaseBytes(_fileBytes(path) + _fileBytes(path + "-wal") + _fileBytes(path + "-shm") + _fileBytes(path + "-journal"));
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            health.RecordFileObservationFailure();
        }
    }

    internal static async Task CheckpointAsync(HoneypotDbContext db, CancellationToken cancellationToken)
    {
        var connection = db.Database.GetDbConnection();
        if (connection.DataSource is "" or ":memory:") return;
        // 只推进当前可用的 WAL 帧，不为截断日志阻塞活动读写。
        await using var command = connection.CreateCommand();
        command.CommandTimeout = 2;
        command.CommandText = "PRAGMA main.wal_checkpoint(PASSIVE)";
        await command.ExecuteScalarAsync(cancellationToken);
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

    private static long Length(string path)
    {
        try { return new FileInfo(path).Length; }
        catch (FileNotFoundException) { return 0; }
    }
}
