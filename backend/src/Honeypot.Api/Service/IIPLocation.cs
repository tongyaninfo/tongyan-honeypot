using Honeypot.Shared.Models;

namespace Honeypot.Api.Service;

/// <summary>外部 IP 查询适配器，仅由后台解析任务调用。</summary>
public interface IIPLocation
{
    Task<IPLocationResult> ResolveAsync(string ip, IPLocationSettings settings, CancellationToken cancellationToken);
}
