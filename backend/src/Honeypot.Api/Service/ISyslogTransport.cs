namespace Honeypot.Api.Service;

/// <summary>投递阶段不等同于远端持久化；只有 RELP 提供应用层确认。</summary>
public enum SyslogDeliveryStage
{
    LocalSubmitted,
    TransportWritten,
    RelpAcknowledged
}

public sealed record SyslogSendResult(SyslogDeliveryStage Stage);

/// <summary>单目标长连接传输；调用方保留未确认记录并决定重试策略。</summary>
public interface ISyslogTransport : IAsyncDisposable
{
    Task ConnectAsync(CancellationToken cancellationToken = default);
    Task<SyslogSendResult> SendAsync(ReadOnlyMemory<byte> message, CancellationToken cancellationToken = default);
}
