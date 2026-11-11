using Honeypot.Api.Models;

namespace Honeypot.Api.Service;

public interface ICredentialEvidenceAccessService
{
    CredentialEvidenceReadResult Read(string artifactId, AuthenticatedUser? user);
    CredentialEvidenceReadResult ReadForExport(string artifactId, AuthenticatedUser? user);
    void AuditExportDenied(AuthenticatedUser? user);
    IReadOnlyCollection<CredentialEvidenceAudit> GetAuditTrail();
}
