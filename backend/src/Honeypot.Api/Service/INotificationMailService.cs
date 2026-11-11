using Honeypot.Shared.Models;

namespace Honeypot.Api.Service;

public interface INotificationMailService
{
    Task<NotificationTaskResult> QueueTestAsync(TestEmailRequest request, string requestedBy, CancellationToken cancellationToken = default);
    Task<NotificationTaskResult> QueueReportAsync(ReportSendRequest request, string requestedBy, CancellationToken cancellationToken = default);
    Task<NotificationTaskResult> RetryAsync(string id, string requestedBy, CancellationToken cancellationToken = default);
    Task<NotificationPage<EmailDeliverySummary>> GetDeliveriesAsync(EmailDeliveryQuery query, CancellationToken cancellationToken = default);
    Task<EmailDeliveryDetails?> GetDeliveryAsync(string id, CancellationToken cancellationToken = default);
    Task<NotificationPage<ReportHistoryItem>> GetReportsAsync(int page, int pageSize, string? kind, CancellationToken cancellationToken = default);
    Task<OperationReport?> GetReportAsync(string id, CancellationToken cancellationToken = default);
    Task ProcessPendingAsync(CancellationToken cancellationToken = default);
    Task ScheduleDueReportsAsync(CancellationToken cancellationToken = default);
}
