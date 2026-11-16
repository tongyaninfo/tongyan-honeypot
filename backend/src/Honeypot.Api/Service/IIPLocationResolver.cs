using Honeypot.Shared.Models;

namespace Honeypot.Api.Service;

public interface IIPLocationResolver
{
    /// <summary>只读本地缓存并尝试入队，绝不等待网络或队列容量。</summary>
    IPLocationBatchResult Resolve(IReadOnlyList<string> ips);

    /// <summary>地图批量读取已有结果，未入队的来源可在下次地图刷新后继续解析。</summary>
    IPLocationBatchResult ResolveForMap(IReadOnlyList<string> ips) => Resolve(ips);
}
