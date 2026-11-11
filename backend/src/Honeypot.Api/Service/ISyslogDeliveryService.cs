using Honeypot.Shared.Models;

namespace Honeypot.Api.Service;

public interface ISyslogDeliveryService
{
    SyslogDeliveryStatus GetStatus();
    Task<SyslogTestResult> TestAsync(string targetId, string? message = null, CancellationToken cancellationToken = default);
}
