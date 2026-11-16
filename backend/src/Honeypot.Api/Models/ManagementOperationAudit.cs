namespace Honeypot.Api.Models;

public sealed record ManagementOperationAudit(
    string Id, DateTimeOffset OccurredAtUtc, string Operation, string? ActorUserId, string? ResourceId, string State, int? HttpStatus);
