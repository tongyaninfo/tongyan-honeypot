using System.Text.Json.Serialization;

namespace Honeypot.Api.Models;

public sealed record CredentialEvidenceSummary(
    string CredentialArtifactId,
    string ConnectionId,
    string EventId,
    string SourceIp,
    string AdapterKey,
    string MaterialType,
    DateTimeOffset CapturedAtUtc,
    DateTimeOffset RetentionUntilUtc,
    bool Truncated);

public sealed record CredentialEvidenceView(
    CredentialEvidenceSummary Summary,
    string Content);

public sealed record CredentialEvidenceExportRequest(string?[]? ArtifactIds);

public sealed record CredentialEvidenceExportItem(
    string ArtifactId,
    string Outcome,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] CredentialEvidenceView? Evidence);
