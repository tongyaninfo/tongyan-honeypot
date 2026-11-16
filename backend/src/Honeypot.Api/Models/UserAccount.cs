namespace Honeypot.Api.Models;

/// <summary>用户持久化记录，不保存明文密码。</summary>
public sealed record UserAccount(
    string UserId,
    string Username,
    string PasswordHash,
    string PasswordSalt,
    IReadOnlyList<string> Roles,
    DateTimeOffset CreatedAtUtc,
    bool Disabled);

public sealed record AuthenticatedUser(string UserId, string Username, IReadOnlyList<string> Roles);

public sealed record LoginResult(string AccessToken, DateTimeOffset ExpiresAtUtc, AuthenticatedUser User);

public sealed record LoginAttemptResult(LoginResult? Session = null, DateTimeOffset? LockedUntilUtc = null, bool Busy = false,
    bool LockoutStarted = false);
