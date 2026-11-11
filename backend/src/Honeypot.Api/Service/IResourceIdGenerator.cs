namespace Honeypot.Api.Service;

/// <summary>通知和报告统一通过此入口发号；对外保持字符串合同，便于接入集中 ID 服务。</summary>
public interface IResourceIdGenerator
{
    string NewId();
}
