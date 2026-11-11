namespace Honeypot.Api.Service.impl;

/// <summary>当前单机阶段沿用项目 GUID 标识策略；新模块不自行维护自增序列。</summary>
public sealed class ResourceIdGenerator : IResourceIdGenerator
{
    public string NewId() => Guid.NewGuid().ToString("N");
}
