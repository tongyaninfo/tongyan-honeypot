using Honeypot.Api.Models;
using Honeypot.Api.Common;

namespace Honeypot.Api.Service;

public interface ICredentialEvidenceAccessService
{
    CredentialEvidenceReadResult Read(string artifactId, AuthenticatedUser? user);
    CredentialEvidenceReadResult ReadForExport(string artifactId, AuthenticatedUser? user);
    void AuditExportDenied(AuthenticatedUser? user);
    IReadOnlyCollection<CredentialEvidenceAudit> GetAuditTrail();
    QueryPageResult<CredentialEvidenceAudit> GetAuditPage(int? page, int? pageSize) => QueryPage.Create(GetAuditTrail(), page, pageSize);
}
