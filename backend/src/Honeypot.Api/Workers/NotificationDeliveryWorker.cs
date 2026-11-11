using Honeypot.Api.Service;

namespace Honeypot.Api.Workers;

public sealed class NotificationDeliveryWorker(INotificationMailService mail, ILogger<NotificationDeliveryWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(2));
        while (!stoppingToken.IsCancellationRequested)
        {
            try { await mail.ProcessPendingAsync(stoppingToken); }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (Exception)
            {
                // 日志只记录固定摘要，数据库/SMTP 异常可能包含收件人或配置，不输出堆栈。
                logger.LogWarning("邮件发送任务暂时失败，已保留发件箱状态供下轮恢复。");
            }
            try { if (!await timer.WaitForNextTickAsync(stoppingToken)) break; }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
        }
    }
}
