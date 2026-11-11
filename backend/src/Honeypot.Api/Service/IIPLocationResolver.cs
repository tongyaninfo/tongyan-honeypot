using Honeypot.Shared.Models;

namespace Honeypot.Api.Service;

public interface IIPLocationResolver
{
    /// <summary>只读本地缓存并尝试入队，绝不等待网络或队列容量。</summary>
    IPLocationBatchResult Resolve(IReadOnlyList<string> ips);
}
