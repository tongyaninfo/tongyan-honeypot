using Honeypot.Api.Models;

namespace Honeypot.Api.Service;

public interface IConnectionMapTarget
{
    /// <summary>只读当前部署目标的快照，网络和文件操作由后台任务处理。</summary>
    ConnectionMapTarget GetSnapshot();
}
