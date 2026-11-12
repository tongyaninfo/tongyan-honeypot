using Honeypot.Api.Service;
using Honeypot.Api.Service.impl;

namespace Honeypot.Api.Workers;

/// <summary>独立于 MCP 开关清理过期记录，每批单独提交以让出 SQLite 写锁。</summary>
public sealed class McpAuditRetentionWorker(SqliteMcpStore store, McpAuditHealth health, ILogger<McpAuditRetentionWorker> logger)
    : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        const int batchSize = 1000;
        using var timer = new PeriodicTimer(TimeSpan.FromMinutes(1));
        do
        {
            try
            {
                for (var batch = 0; batch < 10; batch++)
                {
                    if (await store.DeleteExpiredAuditsAsync(batchSize, stoppingToken) < batchSize) break;
                    await Task.Delay(TimeSpan.FromMilliseconds(50), stoppingToken);
                }
                health.SetRetentionAvailable(true);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception error)
            {
                // 日志只记录异常类型，避免将 SQLite 参数和审计正文写入日志。
                health.SetRetentionAvailable(false);
                logger.LogWarning("MCP audit retention failed. ExceptionType={ExceptionType}", error.GetType().Name);
            }
        } while (await timer.WaitForNextTickAsync(stoppingToken));
    }
}
