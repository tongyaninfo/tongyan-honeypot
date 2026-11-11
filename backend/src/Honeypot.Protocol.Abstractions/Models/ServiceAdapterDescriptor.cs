namespace Honeypot.Protocol.Abstractions.Models;

public sealed record ServiceAdapterDescriptor
{
    public required string AdapterKey { get; init; }
    public required string DisplayName { get; init; }
    public string Version { get; init; } = "1";
    public IReadOnlyList<string> SupportedTransports { get; init; } = new[] { "tcp" };
    public IReadOnlyList<string> SupportedFidelityLevels { get; init; } = new[] { "L0", "L1" };
    public IReadOnlyList<string> SupportedClients { get; init; } = Array.Empty<string>();
    // 只描述新建实例的建议值，持久化配置和实际绑定端口独立处理。
    public string Category => ServiceAdapterDefaults.For(AdapterKey).Category;
    public string? SystemGroup => ServiceAdapterDefaults.For(AdapterKey).SystemGroup;
    public string DefaultInstanceName => ServiceAdapterDefaults.For(AdapterKey).InstanceName;
    public int DefaultPort => ServiceAdapterDefaults.For(AdapterKey).Port;
    public string DefaultHostName => ServiceAdapterDefaults.For(AdapterKey).HostName;
    public string DefaultProduct => ServiceAdapterDefaults.For(AdapterKey).Product;
    public string DefaultProductVersion => ServiceAdapterDefaults.For(AdapterKey).ProductVersion;
}
