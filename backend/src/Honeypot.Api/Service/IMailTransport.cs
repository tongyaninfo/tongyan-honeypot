using Honeypot.Api.Models;

namespace Honeypot.Api.Service;

public interface IMailTransport
{
    Task<MailTransportResult> SendAsync(NotificationTransportSettings settings, MailTransportMessage message,
        CancellationToken cancellationToken = default);
}
