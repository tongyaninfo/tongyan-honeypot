using Honeypot.Api.Models;

namespace Honeypot.Api.Common;

/// <summary>复用真实身份服务的 Administrator 角色，同时兼容早期 admin 标识；不更改账户数据。</summary>
public static class UserAuthorization
{
    public static bool IsAdministrator(AuthenticatedUser? user) => user?.Roles.Any(role =>
        role.Equals("Administrator", StringComparison.OrdinalIgnoreCase) ||
        role.Equals("admin", StringComparison.OrdinalIgnoreCase)) == true;
}
