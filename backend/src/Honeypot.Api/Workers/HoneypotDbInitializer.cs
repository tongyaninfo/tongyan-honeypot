using Honeypot.Api.Data;
using Honeypot.Api.Service;
using Honeypot.Shared.Models;
using Microsoft.EntityFrameworkCore;

namespace Honeypot.Api.Workers;

/// <summary>
/// 应用启动时执行增量迁移。迁移失败直接阻止应用就绪，避免 API 使用不完整的配置表。
/// </summary>
public sealed class HoneypotDbInitializer : IHostedService
{
    private readonly IDbContextFactory<HoneypotDbContext> _dbContextFactory;
    private readonly ISyslogPublisher? _logs;

    public HoneypotDbInitializer(IDbContextFactory<HoneypotDbContext> dbContextFactory, ISyslogPublisher? logs = null)
    {
        _dbContextFactory = dbContextFactory;
        _logs = logs;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        _logs?.Publish("honeypot-storage", "DATABASE_INITIALIZING", SyslogSeverity.Notice);
        try
        {
            await using var db = await _dbContextFactory.CreateDbContextAsync(cancellationToken);
            await db.Database.MigrateAsync(cancellationToken);
            await db.Database.ExecuteSqlRawAsync("PRAGMA foreign_keys = ON;", cancellationToken);
            _logs?.Publish("honeypot-storage", "DATABASE_READY", SyslogSeverity.Notice);
        }
        catch (Exception error) when (error is not OperationCanceledException)
        {
            _logs?.Publish("honeypot-storage", "DATABASE_STARTUP_FAILED", SyslogSeverity.Critical,
                new Dictionary<string, object?> { ["exceptionType"] = error.GetType().Name });
            throw;
        }
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
