namespace Honeypot.Engine.Models;

public enum ThreatDecision
{
    Ignore = 0,
    Observe = 1,
    Block = 2,
}

public sealed record ThreatDecisionResult(
    ThreatDecision Decision,
    string Reason,
    DateTimeOffset EvaluatedAtUtc);
