using Honeypot.Shared.Models;

namespace Honeypot.Api.Service;

public interface IReportService
{
    Task<OperationReport> GenerateAsync(ReportQuery query, CancellationToken cancellationToken = default);
}
