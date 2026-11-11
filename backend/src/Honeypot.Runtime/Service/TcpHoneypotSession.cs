using System.Net;
using System.Net.Sockets;
using Honeypot.Protocol.Abstractions.Models;
using Honeypot.Protocol.Abstractions.Service;
using Honeypot.Runtime.Common;

namespace Honeypot.Runtime.Service;

public sealed class TcpHoneypotSession : IHoneypotSession, IRawStreamHoneypotSession
{
    private readonly TcpClient _client;
    private readonly SessionBudgetStream _stream;
    private int _closed;
    private int _closeReason = -1;

    public TcpHoneypotSession(TcpClient client, string connectionId, long maxSessionBytes = long.MaxValue)
    {
        _client = client;
        ConnectionId = connectionId;
        _stream = new SessionBudgetStream(client.GetStream(), maxSessionBytes);
        RemoteEndPoint = client.Client.RemoteEndPoint ?? new IPEndPoint(IPAddress.None, 0);
        LocalEndPoint = client.Client.LocalEndPoint ?? new IPEndPoint(IPAddress.None, 0);
    }

    public string ConnectionId { get; }
    public EndPoint RemoteEndPoint { get; }
    public EndPoint LocalEndPoint { get; }
    public string Transport => "tcp";
    public bool IsClosed => Volatile.Read(ref _closed) == 1;
    public SessionCloseReason? CloseReason => Volatile.Read(ref _closeReason) is var value && value >= 0
        ? (SessionCloseReason)value : null;
    public Stream RawStream => _stream;
    public bool ResourceLimitExceeded => _stream.LimitExceeded;

    public ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken) =>
        _stream.ReadAsync(buffer, cancellationToken);

    public ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken) =>
        _stream.WriteAsync(buffer, cancellationToken);

    public async ValueTask CloseAsync(SessionCloseReason reason, CancellationToken cancellationToken = default)
    {
        // 部分适配器以空读正常返回；不能把对端 EOF 记作本地协议流程完成。
        if (reason == SessionCloseReason.AdapterCompleted && _stream.PeerClosed) reason = SessionCloseReason.ClientClosed;
        Interlocked.CompareExchange(ref _closeReason, (int)reason, -1);
        if (Interlocked.Exchange(ref _closed, 1) == 1)
        {
            return;
        }

        try { await _stream.DisposeAsync(); }
        finally { _client.Dispose(); }
    }

    public ValueTask DisposeAsync() => CloseAsync(SessionCloseReason.AdapterCompleted);
}
