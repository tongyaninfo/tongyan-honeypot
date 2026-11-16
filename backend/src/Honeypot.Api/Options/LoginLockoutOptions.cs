using Microsoft.Extensions.Configuration;

namespace Honeypot.Api.Options;

public sealed record LoginLockoutOptions(int MaxFailedAttempts, TimeSpan Duration)
{
    public static LoginLockoutOptions Read(IConfiguration configuration)
    {
        var section = configuration.GetSection("Honeypot:LoginLockout");
        var attempts = section.GetValue("MaxFailedAttempts", 5);
        var minutes = section.GetValue("DurationMinutes", 30);
        if (attempts is < 1 or > 100 || minutes is < 1 or > 1440)
            throw new InvalidOperationException("登录锁定配置无效。失败阈值须为 1–100，锁定分钟数须为 1–1440。");

        return new(attempts, TimeSpan.FromMinutes(minutes));
    }
}
