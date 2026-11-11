namespace Honeypot.Protocols.MsSql.Models;

/// <summary>仅在认证处理栈使用的登录材料，不进入普通事件或管理列表。</summary>
internal sealed record TdsLoginMessage(uint Version, string Username, string Password, string? ChangePassword,
    string Database, string HostName, string ApplicationName, bool IntegratedSecurity, byte[] Sspi, bool FederatedAuthentication);
