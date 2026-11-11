namespace Honeypot.Api.Models;

public sealed record InitializeAdminRequest(string Username, string Password);
public sealed record LoginRequest(string Username, string Password);
public sealed record CreateUserRequest(string Username, string Password, IReadOnlyCollection<string>? Roles);

public sealed record RestartPolicyRequest(bool AutoStart);
public sealed record UserInfo(string UserId, string Username, IReadOnlyCollection<string> Roles, DateTimeOffset CreatedAtUtc);
public sealed record SetupStatus(bool Initialized, bool RequiresSetup);
