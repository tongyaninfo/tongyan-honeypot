using System.Net;
using System.Net.Sockets;
using Honeypot.Protocol.Abstractions.Models;
using Honeypot.Protocol.Abstractions.Service;

namespace Honeypot.Runtime.Service.impl;

public sealed class TcpHoneypotSession : IHoneypotSession, IRawStreamHoneypotSession
{
    private readonly TcpClient _client;
    private readonly NetworkStream _stream;
    private int _closed;

    public TcpHoneypotSession(string connectionId, TcpClient client)
    {
        ConnectionId = connectionId;
        _client = client;
        _stream = client.GetStream();
    }

    public string ConnectionId { get; }
    public EndPoint RemoteEndPoint => _client.Client.RemoteEndPoint ?? new IPEndPoint(IPAddress.None, 0);
    public EndPoint LocalEndPoint => _client.Client.LocalEndPoint ?? new IPEndPoint(IPAddress.None, 0);
    public string Transport => "tcp";
    public bool IsClosed => Volatile.Read(ref _closed) == 1;
    public Stream RawStream => _stream;

    public ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken) =>
        _stream.ReadAsync(buffer, cancellationToken);

    public ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken) =>
        _stream.WriteAsync(buffer, cancellationToken);

    public async ValueTask CloseAsync(SessionCloseReason reason, CancellationToken cancellationToken = default)
    {
        if (Interlocked.Exchange(ref _closed, 1) == 1)
        {
            return;
        }

        await _stream.DisposeAsync();
        _client.Dispose();
    }

    public ValueTask DisposeAsync() => CloseAsync(SessionCloseReason.ClientClosed);
}
