namespace Honeypot.Api.Options;

/// <summary>部署目标的可选配置；保留原始数值文本，以便无效配置降级而不影响宿主启动。</summary>
internal sealed record ConnectionMapTargetOptions(string? Label, string? Latitude, string? Longitude, string? PublicIp)
{
    private const string SectionName = "Honeypot:AttackMap:Target";

    public static ConnectionMapTargetOptions Read(IConfiguration configuration)
    {
        var section = configuration.GetSection(SectionName);
        return new(ReadValue("Label"), ReadValue("Latitude"), ReadValue("Longitude"), ReadValue("PublicIp"));

        string? ReadValue(string key) => section[key]?.Trim() is { Length: > 0 } value ? value : null;
    }
}
