using Honeypot.Protocol.Abstractions.Service;
using Honeypot.Runtime.Options;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Honeypot.Runtime.Service;

/// <summary>
/// 只注册运行时核心组件；应用层通常使用 AddHoneypotRuntime 注册完整运行时。
/// </summary>
public static class RuntimeServiceCollectionExtensions
{
    public static IServiceCollection AddHoneypotRuntimeCore(this IServiceCollection services)
    {
        services.AddSingleton<IProtocolAdapterRegistry, ProtocolAdapterRegistry>();
        services.AddSingleton<IConnectionIdGenerator, ConnectionIdGenerator>();
        services.AddOptions<ConnectionAdmissionOptions>()
            .Configure<IServiceProvider>((options, provider) => provider.GetService<IConfiguration>()?
                .GetSection(ConnectionAdmissionOptions.SectionName).Bind(options))
            .Validate(options => options.IsValid(), "Honeypot:ConnectionAdmission 配置无效。")
            .ValidateOnStart();
        services.AddSingleton<IListenerHost, TcpListenerHost>();
        return services;
    }
}
