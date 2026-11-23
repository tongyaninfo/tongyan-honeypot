using System.Text;
using Honeypot.Api.Models;
using Honeypot.Api.Service;
using Honeypot.Protocol.Abstractions.Models;
using Microsoft.Data.Sqlite;

namespace Honeypot.Storage.LoadTest;

internal sealed record LedgerResult(int ExpectedConnections, int MatchedConnections, int ExpectedAuthentications, int MatchedAuthentications,
    int ExpectedSteps, int MissingSteps, int UnsolicitedSteps, int UnexpectedConnections, int UnexpectedEvidence, bool RiskCountMatches);

internal static class Reconciliation
{
    private sealed record Step(string Id, string Connection, int Sequence, string Kind, string Source, string Adapter, string? Artifact, bool EvidenceLinked);
    private sealed record Trace(string AdmissionId, string Admission, string Source, string Adapter, int Observed, int Auth, SessionCloseReason? CloseReason);
    public static LedgerResult Read(string directory, List<ExpectedSession> sessions, ICredentialEvidenceAccessService access, AuthenticatedUser admin)
    {
        using var db = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = Path.Combine(directory, "honeypot.db"), Mode = SqliteOpenMode.ReadOnly }.ToString());
        db.Open();
        using var command = db.CreateCommand();
        command.CommandText = """
            SELECT d.EventId,d.ConnectionId,d.Sequence,d.EventType,d.SourceIp,d.AdapterKey,
                f.CredentialArtifactId, e.ArtifactId IS NOT NULL AND e.EventId=d.EventId AND e.ConnectionId=d.ConnectionId
                  AND e.SourceIp=d.SourceIp AND e.AdapterKey=d.AdapterKey AND ((e.MaterialType='Plaintext')=(e.PasswordBookOccurredAtUtcTicks IS NOT NULL))
                  AND json_extract(d.EventJson,'$.CredentialArtifactId')=e.ArtifactId
            FROM interaction_events d JOIN report_events f ON f.EventId=d.EventId
            LEFT JOIN credential_evidence e ON e.ArtifactId=f.CredentialArtifactId
            WHERE d.ConnectionId LIKE 'live-%'
            """;
        var steps = new Dictionary<string, Step>();
        using (var rows = command.ExecuteReader())
            while (rows.Read())
                steps.Add(rows.GetString(0), new(rows.GetString(0), rows.GetString(1), rows.GetInt32(2), rows.GetString(3),
                    rows.GetString(4), rows.GetString(5), rows.IsDBNull(6) ? null : rows.GetString(6), !rows.IsDBNull(7) && rows.GetInt32(7) == 1));
        command.CommandText = """
            SELECT ConnectionId,coalesce(AdmissionEventId,''),coalesce(AdmissionOutcome,''),SourceIp,AdapterKey,ObservedCount,
            AuthenticationActivityCount,CASE WHEN ClosedAtUtcTicks IS NOT NULL THEN CloseReason END
            FROM connection_summaries WHERE ConnectionId LIKE 'live-%'
            """;
        var traces = new Dictionary<string, Trace>();
        using (var rows = command.ExecuteReader())
            while (rows.Read())
                traces.Add(rows.GetString(0), new(rows.GetString(1), rows.GetString(2), rows.GetString(3), rows.GetString(4),
                    rows.GetInt32(5), rows.GetInt32(6), rows.IsDBNull(7) ? null : (SessionCloseReason)rows.GetInt32(7)));
        command.CommandText = "SELECT count(*) FROM credential_evidence WHERE ConnectionId LIKE 'live-%'";
        var evidenceRows = Convert.ToInt32(command.ExecuteScalar());
        command.CommandText = "SELECT coalesce(sum(AttemptCount),0) FROM threat_ip_profiles WHERE SourceIp LIKE '2001:db8:%'";
        var riskCount = Convert.ToInt32(command.ExecuteScalar());
        using var connections = new StreamWriter(Path.Combine(directory, "connections.csv"));
        using var authentications = new StreamWriter(Path.Combine(directory, "authentications.csv"));
        connections.WriteLine("phase,adapter,connection_id,source,admission,close_reason,expected_steps,observed_steps,expected_authentications,recorded_authentications,pass");
        authentications.WriteLine("phase,adapter,connection_id,attempt,sequence,event_id,material_type,artifact_id,lookup_and_decryption_match");
        var expectedAuth = 0;
        var matchedAuth = 0;
        var missingSteps = 0;
        var matchedConnections = 0;
        var linkedArtifacts = new HashSet<string>();
        foreach (var session in sessions)
        {
            var authCount = session.Kinds.Count(kind => kind == "AuthenticationAttempted");
            expectedAuth += authCount;
            traces.Remove(session.ConnectionId, out var trace);
            var ok = trace is { Admission: "accepted" } && trace.CloseReason == LiveReplay.CloseReason(session) && trace.AdmissionId == LiveReplay.EventId(session, 1)
                && trace.Source == session.Source && trace.Adapter == session.Adapter && trace.Observed == session.Kinds.Length && trace.Auth == authCount;
            var attempt = 0;
            for (var i = 0; i < session.Kinds.Length; i++)
            {
                var id = LiveReplay.EventId(session, i + 1);
                steps.Remove(id, out var step);
                var matched = step is not null && step.Sequence == i + 1 && step.Connection == session.ConnectionId && step.Kind == session.Kinds[i]
                    && step.Source == session.Source && step.Adapter == session.Adapter;
                if (!matched) missingSteps++;
                if (session.Kinds[i] == "AuthenticationAttempted")
                {
                    var artifact = step?.Artifact;
                    var material = artifact is null ? null : access.ReadForExport(artifact, admin).Evidence;
                    matched &= step?.EvidenceLinked == true && artifact is not null && linkedArtifacts.Add(artifact) &&
                        material?.Summary.MaterialType == LiveReplay.Material(session) && material.Summary.EventId == id && material.Summary.ConnectionId == session.ConnectionId &&
                        material.Content == Encoding.UTF8.GetString(LiveReplay.Evidence(session, i + 1));
                    authentications.WriteLine($"{session.Phase},{session.Adapter},{session.ConnectionId},{++attempt},{i + 1},{id},{LiveReplay.Material(session)},{artifact},{matched}");
                    if (matched) matchedAuth++;
                }
                ok &= matched;
            }
            connections.WriteLine($"{session.Phase},{session.Adapter},{session.ConnectionId},{session.Source},{trace?.Admission},{trace?.CloseReason},{session.Kinds.Length},{trace?.Observed},{authCount},{trace?.Auth},{ok}");
            if (ok) matchedConnections++;
        }
        var total = sessions.Sum(s => s.Kinds.Length);
        return new(sessions.Count, matchedConnections, expectedAuth, matchedAuth, total, missingSteps, steps.Count, traces.Count,
            evidenceRows - linkedArtifacts.Count, riskCount == total);
    }
}
