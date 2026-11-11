using Honeypot.Api.Models;
using Honeypot.Shared.Models;

namespace Honeypot.Api.Service;

public interface INotificationSettingsStore
{
    Task<NotificationSettings> GetAsync(CancellationToken cancellationToken = default);
    Task<NotificationSettings> SaveAsync(UpdateNotificationSettingsRequest request, CancellationToken cancellationToken = default);
    Task<NotificationTransportSettings> GetTransportAsync(CancellationToken cancellationToken = default);
    Task<IReadOnlyList<NotificationScheduleState>> GetScheduleStatesAsync(CancellationToken cancellationToken = default);
    Task RecordScheduleRunAsync(string kind, DateTimeOffset? scheduledAtUtc, string status, CancellationToken cancellationToken = default);
}
