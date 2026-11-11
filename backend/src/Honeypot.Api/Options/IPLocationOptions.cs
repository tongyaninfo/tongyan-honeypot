namespace Honeypot.Api.Options;

/// <summary>资源上限由服务端固定控制，管理页面不能放大队列或并发。</summary>
public sealed record IPLocationOptions
{
    public int QueueCapacity { get; init; } = 1024;
    public int Concurrency { get; init; } = 4;
    public int CacheCapacity { get; init; } = 10000;
    public TimeSpan SuccessLifetime { get; init; } = TimeSpan.FromHours(24);
    public TimeSpan FailureLifetime { get; init; } = TimeSpan.FromMinutes(1);
}
