using Honeypot.Api.Data;
using Honeypot.Api.Data.Models;
using Honeypot.Shared.Models;
using Microsoft.EntityFrameworkCore;

namespace Honeypot.Api.Service.impl;

/// <summary>将通知健康补到同一统计快照，页面与邮件不会各自计算不同口径。</summary>
public sealed class ReportWithMailSummaryService(
    SqliteReportService reports,
    IDbContextFactory<HoneypotDbContext> factory,
    ISyslogPublisher? logs = null) : IReportService
{
    public async Task<OperationReport> GenerateAsync(ReportQuery query, CancellationToken cancellationToken = default)
    {
        var report = await reports.GenerateAsync(query, cancellationToken);
        var start = report.Period.StartAtUtc.ToUnixTimeMilliseconds();
        var end = report.Period.EndAtUtc.ToUnixTimeMilliseconds();
        await using var db = await factory.CreateDbContextAsync(cancellationToken);
        var states = await db.Set<EmailDeliveryEntity>().AsNoTracking()
            .Where(item => item.CreatedUnixMs >= start && item.CreatedUnixMs < end)
            .GroupBy(item => item.Status).Select(group => new { Status = group.Key, Count = group.LongCount() })
            .ToDictionaryAsync(item => item.Status, item => item.Count, cancellationToken);
        logs?.Publish("honeypot-report", "REPORT_GENERATED", SyslogSeverity.Informational);
        return report with
        {
            MailSummary = new(states.GetValueOrDefault("Accepted"), states.GetValueOrDefault("Failed"),
                states.GetValueOrDefault("Pending"), states.GetValueOrDefault("Retrying"),
                states.GetValueOrDefault("Unknown"), states.GetValueOrDefault("Sending")),
            Notes = [.. report.Notes, "邮件统计为本统计区间内创建的投递任务在报告生成时的状态；SMTP 已受理不表示已到达或已读。"],
        };
    }
}
