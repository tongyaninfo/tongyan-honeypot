using Honeypot.Api.Models;

namespace Honeypot.Api.Service;

public interface IUserIdentityService
{
    bool IsInitialized { get; }
    Task<(bool Succeeded, string Code, string Message)> InitializeFirstAdminAsync(string username, string password, CancellationToken cancellationToken = default);
    Task<LoginResult?> LoginAsync(string username, string password, CancellationToken cancellationToken = default);
    bool TryAuthenticate(string accessToken, out AuthenticatedUser? user);
    void Logout(string accessToken);
    IReadOnlyCollection<AuthenticatedUser> GetUsers();
}
