using Honeypot.Api.Models;

namespace Honeypot.Api.Service;

public interface IIdentityService
{
    bool IsInitialized { get; }
    SetupStatus GetSetupStatus();
    Task<UserInfo> InitializeFirstAdminAsync(string username, string password, CancellationToken cancellationToken = default);
    Task<UserInfo> CreateUserAsync(string username, string password, IReadOnlyCollection<string> roles, CancellationToken cancellationToken = default);
    Task<LoginResult?> LoginAsync(string username, string password, CancellationToken cancellationToken = default);
    UserInfo? ValidateToken(string? accessToken);
    void Logout(string? accessToken);
    IReadOnlyCollection<UserInfo> GetUsers();
}
