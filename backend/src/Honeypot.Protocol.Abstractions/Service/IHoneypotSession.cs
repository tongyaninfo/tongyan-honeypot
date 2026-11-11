using System.Net;
using Honeypot.Protocol.Abstractions.Models;

namespace Honeypot.Protocol.Abstractions.Service;

public interface IHoneypotSession : IAsyncDisposable
{
    string ConnectionId { get; }
    EndPoint RemoteEndPoint { get; }
    EndPoint LocalEndPoint { get; }
    string Transport { get; }
    bool IsClosed { get; }
    // 旧的测试会话或外部适配实现可以不提供原因，真实运行时保留首次关闭原因。
    SessionCloseReason? CloseReason => null;

    ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken);

    ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken);

    ValueTask CloseAsync(SessionCloseReason reason, CancellationToken cancellationToken = default);
}
