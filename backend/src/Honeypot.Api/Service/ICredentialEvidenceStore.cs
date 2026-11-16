using Honeypot.Api.Common;
using Honeypot.Api.Data;
using Honeypot.Api.Models;
using Honeypot.Protocol.Abstractions.Models;

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

    QueryPageResult<CredentialEvidenceSummary> GetPage(int? page, int? pageSize) =>
        QueryPage.Create(GetAll(), page, pageSize);

    void ConfirmPasswordBookAttempt(InteractionEvent acceptedEvent) { }

    Task ConfirmPasswordBookAttemptAsync(HoneypotDbContext db, InteractionEvent acceptedEvent, CancellationToken cancellationToken,
        DateTimeOffset acceptedAtUtc) => Task.CompletedTask;

    IReadOnlyCollection<PasswordBookRow> GetPasswordBook() => [];

    object GetPasswordBookPage(int? page, int? pageSize, string? keyword = null)
    {
        var rows = GetPasswordBook().AsEnumerable();
        if (keyword?.Trim() is { Length: > 0 } filter)
        {
            var needle = PasswordBookProjection.FoldSearchText(filter);
            rows = rows.Where(row => PasswordBookProjection.FoldSearchText(row.Username).Contains(needle, StringComparison.Ordinal) ||
                PasswordBookProjection.FoldSearchText(row.AdapterKey).Contains(needle, StringComparison.Ordinal));
        }
        return QueryPage.Create(rows.OrderByDescending(row => row.LastUsedAtUtc)
            .ThenBy(row => row.CredentialArtifactId, StringComparer.Ordinal), page, pageSize);
    }
}
