using Honeypot.Api.Models;

namespace Honeypot.Api.Service;

public interface ICredentialEvidenceStore
{
    Task<CredentialEvidenceSummary> SaveAsync(
        string connectionId,
        string eventId,
        string sourceIp,
        string adapterKey,
        string materialType,
        string content,
        int retentionDays,
        CancellationToken cancellationToken = default);

    CredentialEvidenceView? Get(string credentialArtifactId);

    IReadOnlyCollection<CredentialEvidenceSummary> GetAll();
}
