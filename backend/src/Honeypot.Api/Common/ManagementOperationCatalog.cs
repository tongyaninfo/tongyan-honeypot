namespace Honeypot.Api.Common;

/// <summary>按固定路由模板识别管理操作，不解析实际请求路径或参数。</summary>
internal static class ManagementOperationCatalog
{
    public const string Login = "AdminLogin";
    public const string Logout = "AdminLogout";
    public const string Initialize = "AdminInitialize";
    public const string NotificationSettings = "NotificationSettingsUpdate";
    public const string IpLocationSettings = "IpLocationSettingsUpdate";
    public const string InstanceSave = "ServiceInstanceSave";
    public const string InstanceApply = "ServiceInstanceApply";
    public const string InstanceStart = "ServiceInstanceStart";
    public const string InstanceStop = "ServiceInstanceStop";
    public const string RestartPolicy = "ServiceInstanceRestartPolicy";

    public static string? Find(string? route, string method) => (route, method) switch
    {
        ("/api/v1/auth/login", "POST") => Login,
        ("/api/v1/auth/logout", "POST") => Logout,
        ("/api/v1/setup/initialize", "POST") => Initialize,
        ("/api/v1/settings/notifications", "PUT") => NotificationSettings,
        ("/api/v1/settings/ip-location", "PUT") => IpLocationSettings,
        ("/api/v1/service-instances", "POST") => InstanceSave,
        ("/api/v1/service-instances/{instanceId}/apply", "POST") => InstanceApply,
        ("/api/v1/service-instances/{instanceId}/start", "POST") => InstanceStart,
        ("/api/v1/service-instances/{instanceId}/stop", "POST") => InstanceStop,
        ("/api/v1/service-instances/{instanceId}/restart-policy", "POST") => RestartPolicy,
        _ => null,
    };
}
