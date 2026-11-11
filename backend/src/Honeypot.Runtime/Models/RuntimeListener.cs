using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using Honeypot.Protocol.Abstractions.Models;

namespace Honeypot.Runtime.Models;

internal sealed class RuntimeListener
{
    public RuntimeListener(
        TcpListener listener,
        ListenerBinding binding,
        ServiceInstance instance,
        CancellationTokenSource cancellation)
    {
        Listener = listener;
        Binding = binding;
        Instance = instance;
        Cancellation = cancellation;
        State = "Starting";
    }

    public TcpListener Listener { get; }
    public ListenerBinding Binding { get; }
    public ServiceInstance Instance { get; }
    public CancellationTokenSource Cancellation { get; }
    public Task? AcceptLoop { get; set; }
    public string State { get; set; }
    public int ActiveConnections;
    public long AcceptedCount;
    public long ErrorCount;
    public string? LastError;
    public ConcurrentDictionary<IPAddress, int> ConnectionsByIp { get; } = new();
    // 停止监听时等待会话的最终事件完成，避免发送服务先退出而漏掉关闭日志。
    public ConcurrentDictionary<Task, byte> Sessions { get; } = new();
}
