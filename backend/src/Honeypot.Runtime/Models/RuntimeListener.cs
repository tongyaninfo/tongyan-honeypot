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
    public long RejectedCount;
    public long EventWriteFailureCount;
    public long LastEventWriteWarningTimestamp = long.MinValue;
    public long ErrorCount;
    public string? LastError;
    // 与所有监听共享同一接纳锁，释放最后一个会话时同时移除来源条目。
    public Dictionary<IPAddress, int> ConnectionsByIp { get; } = new();
    // 仅为通过接纳检查的会话分配，由现有并发额度限制数量。
    public ConcurrentDictionary<string, ActiveConnectionSnapshot> ActiveConnectionDetails { get; } = new(StringComparer.Ordinal);
    // 停止监听时等待会话的最终事件完成，避免发送服务先退出而漏掉关闭日志。
    public ConcurrentDictionary<Task, byte> Sessions { get; } = new();
}
