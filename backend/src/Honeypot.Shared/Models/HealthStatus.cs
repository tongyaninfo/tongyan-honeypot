namespace Honeypot.Shared.Models;

public sealed record HealthStatus(string Service, string Version, DateTimeOffset UtcTime);
