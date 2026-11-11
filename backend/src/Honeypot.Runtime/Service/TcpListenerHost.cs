using System.Net;
using System.Net.Sockets;
using Honeypot.Protocol.Abstractions.Models;
using Honeypot.Protocol.Abstractions.Service;
using Honeypot.Protocols.Common;
using Honeypot.Runtime.Models;
using Microsoft.Extensions.Logging;

namespace Honeypot.Runtime.Service;

/// <summary>
/// 单机 TCP 监听编排器。协议适配器不自行开端口，所有连接先经过这里记录。
/// </summary>
public sealed class TcpListenerHost : IListenerHost
{
    private readonly object _sync = new();
    private readonly IProtocolAdapterRegistry _adapterRegistry;
    private readonly IInteractionEventSink _eventSink;
    private readonly IConnectionIdGenerator _idGenerator;
    private readonly ILogger<TcpListenerHost> _logger;
    private Dictionary<string, RuntimeListener> _listeners = new(StringComparer.Ordinal);
    private bool _disposed;

    public TcpListenerHost(
        IProtocolAdapterRegistry adapterRegistry,
        IInteractionEventSink eventSink,
        IConnectionIdGenerator idGenerator,
        ILogger<TcpListenerHost> logger)
    {
        _adapterRegistry = adapterRegistry;
        _eventSink = eventSink;
        _idGenerator = idGenerator;
        _logger = logger;
    }

    public IReadOnlyCollection<ListenerRuntimeStatus> GetStatuses()
    {
        lock (_sync)
        {
            return _listeners.Values.Select(ToStatus).ToArray();
        }
    }

    public async Task<ListenerApplyResult> ApplyAsync(
        ServiceInstance instance,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(instance);
        ThrowIfDisposed();

        if (!_adapterRegistry.TryGet(instance.AdapterKey, out var adapter) || adapter is null)
        {
            return ListenerApplyResult.Failed(
                "ADAPTER_UNAVAILABLE",
                $"Protocol adapter '{instance.AdapterKey}' is not registered.");
        }

        var adapterValidation = await adapter.ValidateAsync(instance.Profile, cancellationToken);
        if (!adapterValidation.IsValid)
        {
            return ListenerApplyResult.Failed(adapterValidation.Code, adapterValidation.Message);
        }

        var enabledBindings = instance.Bindings.Where(binding => binding.Enabled).ToArray();
        if (enabledBindings.Length == 0)
        {
            return ListenerApplyResult.Failed("NO_ENABLED_BINDING", "No enabled listener binding was provided.");
        }

        var duplicate = enabledBindings
            .GroupBy(binding => ListenerKey(binding.BindAddress, binding.Port, binding.Transport), StringComparer.OrdinalIgnoreCase)
            .FirstOrDefault(group => group.Count() > 1);
        if (duplicate is not null)
        {
            return ListenerApplyResult.Failed("PORT_CONFLICT", $"Listener binding '{duplicate.Key}' is duplicated.");
        }

        Dictionary<string, RuntimeListener> previousSnapshot;
        lock (_sync)
        {
            previousSnapshot = _listeners;
        }

        var currentInstanceListeners = previousSnapshot.Values
            .Where(runtime => runtime.Instance.InstanceId.Equals(instance.InstanceId, StringComparison.OrdinalIgnoreCase))
            .ToArray();
        if (currentInstanceListeners.Length == enabledBindings.Length &&
            enabledBindings.All(binding => currentInstanceListeners.Any(runtime =>
                ListenerKey(runtime.Binding.BindAddress, runtime.Binding.Port, runtime.Binding.Transport)
                    .Equals(ListenerKey(binding.BindAddress, binding.Port, binding.Transport), StringComparison.OrdinalIgnoreCase))))
        {
            return ListenerApplyResult.Applied($"Instance '{instance.InstanceId}' is already running.");
        }

        var preserved = previousSnapshot.Values
            .Where(runtime => !runtime.Instance.InstanceId.Equals(instance.InstanceId, StringComparison.OrdinalIgnoreCase))
            .ToDictionary(runtime => runtime.Binding.ListenerId, StringComparer.Ordinal);

        // 端口编辑是实例级替换：先释放该实例旧 socket，再绑定新的端口集合。
        // 否则修改 A 为 B 时，旧 A 仍占用端口，新的配置会被错误地判定为 BIND_FAILED。
        // 失败时实例保持停止状态，避免状态表继续暴露已经关闭的旧监听器。
        await StopListenersAsync(currentInstanceListeners);
        lock (_sync)
        {
            _listeners = preserved;
        }

        var next = new Dictionary<string, RuntimeListener>(preserved, StringComparer.Ordinal);
        string? bindingLabel = null;
        try
        {
            foreach (var binding in enabledBindings)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (!string.Equals(binding.Transport, "tcp", StringComparison.OrdinalIgnoreCase))
                {
                    throw new ListenerApplyException("UNSUPPORTED_TRANSPORT", $"Transport '{binding.Transport}' is not supported by TcpListenerHost.");
                }

                ValidateBinding(binding);
                if (next.ContainsKey(binding.ListenerId))
                {
                    throw new ListenerApplyException("LISTENER_CONFLICT", $"Listener '{binding.ListenerId}' is already in use.");
                }

                var bindingKey = ListenerKey(binding.BindAddress, binding.Port, binding.Transport);
                bindingLabel = $"{binding.BindAddress}:{binding.Port}/{binding.Transport}";
                if (preserved.Values.Any(existing => ListenerKey(existing.Binding.BindAddress, existing.Binding.Port, existing.Binding.Transport).Equals(bindingKey, StringComparison.OrdinalIgnoreCase)))
                {
                    throw new ListenerApplyException("PORT_CONFLICT", $"Listener binding '{bindingKey}' is already in use.");
                }

                var endpoint = new IPEndPoint(ParseBindAddress(binding.BindAddress), binding.Port);
                var listener = new TcpListener(endpoint);
                listener.Start();
                var runtime = new RuntimeListener(
                    listener,
                    binding,
                    instance,
                    new CancellationTokenSource());
                runtime.State = "Running";
                runtime.AcceptLoop = AcceptLoopAsync(runtime);
                next.Add(binding.ListenerId, runtime);
            }
        }
        catch (ListenerApplyException exception)
        {
            await StopListenersAsync(next.Values.Where(runtime => !preserved.ContainsKey(runtime.Binding.ListenerId)));
            lock (_sync)
            {
                _listeners = preserved;
            }
            return ListenerApplyResult.Failed(exception.Code, exception.Message);
        }
        catch (SocketException exception)
        {
            await StopListenersAsync(next.Values.Where(runtime => !preserved.ContainsKey(runtime.Binding.ListenerId)));
            lock (_sync)
            {
                _listeners = preserved;
            }
            var message = exception.SocketErrorCode switch
            {
                SocketError.AddressAlreadyInUse => $"监听地址 {bindingLabel ?? "当前端口"} 已被其他进程占用，请更换端口后重试。",
                SocketError.AccessDenied => $"监听地址 {bindingLabel ?? "当前端口"} 没有权限，请更换端口或检查服务权限。",
                _ => $"监听地址 {bindingLabel ?? "当前端口"} 启动失败：{exception.Message}",
            };
            return ListenerApplyResult.Failed("BIND_FAILED", message);
        }
        catch (OperationCanceledException)
        {
            await StopListenersAsync(next.Values.Where(runtime => !preserved.ContainsKey(runtime.Binding.ListenerId)));
            lock (_sync)
            {
                _listeners = preserved;
            }
            throw;
        }

        lock (_sync)
        {
            _listeners = next;
        }
        return ListenerApplyResult.Applied($"Applied {next.Count} listener(s) for instance '{instance.InstanceId}'.");
    }

    public async Task StopInstanceAsync(string instanceId, CancellationToken cancellationToken = default)
    {
        Dictionary<string, RuntimeListener> selected;
        lock (_sync)
        {
            selected = _listeners
                .Where(pair => pair.Value.Instance.InstanceId.Equals(instanceId, StringComparison.OrdinalIgnoreCase))
                .ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.Ordinal);
            foreach (var key in selected.Keys)
            {
                _listeners.Remove(key);
            }
        }

        await StopListenersAsync(selected.Values, cancellationToken);
    }

    public async Task StopAsync(CancellationToken cancellationToken = default)
    {
        Dictionary<string, RuntimeListener> previous;
        lock (_sync)
        {
            previous = _listeners;
            _listeners = new Dictionary<string, RuntimeListener>(StringComparer.Ordinal);
        }

        await StopListenersAsync(previous.Values, cancellationToken);
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        await StopAsync();
    }

    private async Task AcceptLoopAsync(RuntimeListener runtime)
    {
        try
        {
            while (!runtime.Cancellation.IsCancellationRequested)
            {
                var client = await runtime.Listener.AcceptTcpClientAsync(runtime.Cancellation.Token);
                runtime.AcceptedCount++;
                var sessionTask = HandleConnectionAsync(runtime, client);
                runtime.Sessions.TryAdd(sessionTask, 0);
                _ = sessionTask.ContinueWith(completed =>
                {
                    runtime.Sessions.TryRemove(completed, out _);
                    if (completed.Exception is not null)
                        _logger.LogError("Listener {ListenerId} session completion failed: {ErrorCode}.", runtime.Binding.ListenerId, "SESSION_COMPLETION_FAILED");
                }, CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
            }
        }
        catch (OperationCanceledException) when (runtime.Cancellation.IsCancellationRequested)
        {
            runtime.State = "Stopped";
        }
        catch (ObjectDisposedException) when (runtime.Cancellation.IsCancellationRequested)
        {
            runtime.State = "Stopped";
        }
        catch (Exception exception)
        {
            runtime.ErrorCount++;
            runtime.LastError = exception.GetType().Name;
            runtime.State = "Failed";
            _logger.LogError("Listener {ListenerId} accept loop failed: {ErrorCode}.", runtime.Binding.ListenerId, runtime.LastError);
        }
    }

    private async Task HandleConnectionAsync(RuntimeListener runtime, TcpClient client)
    {
        var remote = client.Client.RemoteEndPoint as IPEndPoint;
        var remoteIp = remote?.Address ?? IPAddress.None;
        var active = Interlocked.Increment(ref runtime.ActiveConnections);
        var ipActive = runtime.ConnectionsByIp.AddOrUpdate(remoteIp, 1, static (_, current) => current + 1);
        var connectionId = _idGenerator.NewConnectionId();
        var session = new TcpHoneypotSession(client, connectionId, runtime.Instance.Profile.MaxSessionBytes);
        var context = new ProtocolSessionContext(
            connectionId,
            runtime.Binding.ListenerId,
            runtime.Instance.InstanceId,
            runtime.Instance.AdapterKey,
            runtime.Instance.Profile.ProfileId,
            session.RemoteEndPoint,
            session.LocalEndPoint,
            DateTimeOffset.UtcNow);

        var sequencedSink = new SequencedEventSink(_eventSink, _idGenerator, context, 1);
        SessionCloseReason? failureReason = null;
        var failureReported = false;
        try
        {
            var accepted = new InteractionEvent
            {
                EventId = _idGenerator.NewEventId(),
                ConnectionId = connectionId,
                Sequence = 1,
                EventType = "ConnectionAccepted",
                OccurredAtUtc = context.AcceptedAtUtc,
                SourceIp = remoteIp.ToString(),
                SourcePort = remote?.Port ?? 0,
                DestinationIp = GetIp(session.LocalEndPoint),
                DestinationPort = GetPort(session.LocalEndPoint),
                Transport = "tcp",
                ListenerId = runtime.Binding.ListenerId,
                ServiceInstanceId = runtime.Instance.InstanceId,
                AdapterKey = runtime.Instance.AdapterKey,
                ProfileId = runtime.Instance.Profile.ProfileId,
                RiskDelta = 1,
            };

            var appendResult = await _eventSink.AppendAsync(accepted, runtime.Cancellation.Token);
            if (!appendResult.Recorded)
            {
                _logger.LogError("Connection {ConnectionId} was not recorded on listener {ListenerId}: {ErrorCode}.",
                    connectionId, runtime.Binding.ListenerId, appendResult.Code);
                failureReported = true;
                await session.CloseAsync(SessionCloseReason.StorageDegraded);
                return;
            }

            if (active > runtime.Binding.MaxConnections || ipActive > runtime.Binding.MaxConnectionsPerIp)
            {
                await session.CloseAsync(SessionCloseReason.ResourceLimitExceeded);
                return;
            }

            if (!_adapterRegistry.TryGet(runtime.Instance.AdapterKey, out var adapter) || adapter is null)
            {
                await session.CloseAsync(SessionCloseReason.InternalError);
                return;
            }

            using var sessionTimeout = CancellationTokenSource.CreateLinkedTokenSource(runtime.Cancellation.Token);
            sessionTimeout.CancelAfter(runtime.Instance.Profile.IdleTimeout);
            await adapter.HandleAsync(session, context, runtime.Instance.Profile, sequencedSink, sessionTimeout.Token);
        }
        catch (OperationCanceledException) when (runtime.Cancellation.IsCancellationRequested)
        {
            failureReason = SessionCloseReason.ListenerStopping;
        }
        catch (OperationCanceledException)
        {
            failureReason = SessionCloseReason.IdleTimeout;
        }
        catch (Exception exception) when (exception is IOException or SocketException)
        {
            // 远端断开和会话字节预算触发不属于宿主内部错误，不输出底层异常正文。
            failureReason = session.ResourceLimitExceeded ? SessionCloseReason.ResourceLimitExceeded : SessionCloseReason.ClientClosed;
        }
        catch (Exception exception)
        {
            runtime.ErrorCount++;
            // 协议输入不可信，异常消息和堆栈可能包含认证材料，仅暴露固定类型/错误码。
            runtime.LastError = exception is AuthenticationRecordingException recording ? recording.Code : exception.GetType().Name;
            _logger.LogError("Session {ConnectionId} failed on listener {ListenerId}: {ErrorCode}.", connectionId, runtime.Binding.ListenerId, runtime.LastError);
            failureReported = true;
            failureReason = exception is AuthenticationRecordingException ? SessionCloseReason.StorageDegraded : SessionCloseReason.InternalError;
        }
        finally
        {
            var reason = failureReason ?? (session.ResourceLimitExceeded ? SessionCloseReason.ResourceLimitExceeded
                : session.CloseReason ?? SessionCloseReason.AdapterCompleted);
            if (!failureReported && reason is SessionCloseReason.StorageDegraded or SessionCloseReason.InternalError)
            {
                // 部分适配器按既有合同捕获异常并关闭；仍从真实关闭原因发出独立诊断，不能依赖故障事件库。
                _logger.LogError("Session {ConnectionId} closed on listener {ListenerId}: {ErrorCode}.",
                    connectionId, runtime.Binding.ListenerId, reason == SessionCloseReason.StorageDegraded ? "SESSION_STORAGE_DEGRADED" : "SESSION_INTERNAL_ERROR");
            }
            try { await session.CloseAsync(reason); }
            catch (Exception)
            {
                // 资源释放失败单独诊断，不能跳过连接计数回收或伪造正常结束。
                reason = SessionCloseReason.InternalError;
                _logger.LogError("Session {ConnectionId} disposal failed: {ErrorCode}.", connectionId, "SESSION_DISPOSE_FAILED");
            }
            if (reason == SessionCloseReason.AdapterCompleted && session.CloseReason is { } observedReason)
                reason = observedReason;
            Interlocked.Decrement(ref runtime.ActiveConnections);
            runtime.ConnectionsByIp.AddOrUpdate(remoteIp, 0, static (_, current) => Math.Max(0, current - 1));
            if (runtime.ConnectionsByIp.TryGetValue(remoteIp, out var count) && count == 0)
                runtime.ConnectionsByIp.TryRemove(remoteIp, out _);

            // 最终事件只在这里生成一次，覆盖所有早退/异常分支；宿主停止的令牌不能取消关闭留痕。
            using var finalDeadline = new CancellationTokenSource(TimeSpan.FromSeconds(2));
            try
            {
                if (session.ResourceLimitExceeded)
                    await sequencedSink.AppendAsync(new InteractionEvent
                    {
                        EventId = _idGenerator.NewEventId(), ConnectionId = connectionId,
                        EventType = "ResourceLimitExceeded", OccurredAtUtc = DateTimeOffset.UtcNow,
                        SourceIp = remoteIp.ToString(), SourcePort = remote?.Port ?? 0,
                        DestinationIp = GetIp(session.LocalEndPoint), DestinationPort = GetPort(session.LocalEndPoint),
                        ListenerId = context.ListenerId, ServiceInstanceId = context.ServiceInstanceId,
                        AdapterKey = context.AdapterKey, ProfileId = context.ProfileId,
                        Stage = "transport", Outcome = "resource_limit", PayloadSummary = "Session byte limit exceeded",
                    }, finalDeadline.Token).AsTask().WaitAsync(finalDeadline.Token);
            }
            catch (Exception)
            {
                _logger.LogError("Session {ConnectionId} limit event could not be recorded: {ErrorCode}.", connectionId, "SESSION_LIMIT_RECORD_FAILED");
            }
            using var closeDeadline = new CancellationTokenSource(TimeSpan.FromSeconds(2));
            try
            {
                var closed = new InteractionEvent
                {
                    EventId = _idGenerator.NewEventId(), ConnectionId = connectionId, EventType = "SessionClosed",
                    OccurredAtUtc = DateTimeOffset.UtcNow, SourceIp = remoteIp.ToString(), SourcePort = remote?.Port ?? 0,
                    DestinationIp = GetIp(session.LocalEndPoint), DestinationPort = GetPort(session.LocalEndPoint),
                    Transport = "tcp", ListenerId = context.ListenerId, ServiceInstanceId = context.ServiceInstanceId,
                    AdapterKey = context.AdapterKey, ProfileId = context.ProfileId, Stage = "closed", CloseReason = reason,
                    Outcome = reason switch
                    {
                        SessionCloseReason.StorageDegraded => "storage_failed",
                        SessionCloseReason.InternalError => "internal_error",
                        SessionCloseReason.ResourceLimitExceeded => "resource_limit",
                        SessionCloseReason.ProtocolViolation => "protocol_violation",
                        SessionCloseReason.HandshakeTimeout or SessionCloseReason.IdleTimeout => "timeout",
                        SessionCloseReason.ListenerStopping => "listener_stopping",
                        SessionCloseReason.ClientClosed => "client_closed",
                        _ => "completed",
                    },
                };
                var closedResult = await sequencedSink.AppendAsync(closed, closeDeadline.Token).AsTask().WaitAsync(closeDeadline.Token);
                if (!closedResult.Recorded)
                    _logger.LogError("Session {ConnectionId} close event was not recorded: {ErrorCode}.", connectionId, closedResult.Code);
            }
            catch (Exception)
            {
                _logger.LogError("Session {ConnectionId} close event could not be recorded: {ErrorCode}.", connectionId, "SESSION_CLOSE_RECORD_FAILED");
            }
        }
    }

    private static void ValidateBinding(ListenerBinding binding)
    {
        if (binding.Port is < 1 or > 65535)
        {
            throw new ListenerApplyException("INVALID_PORT", $"Port '{binding.Port}' is outside 1-65535.");
        }

        if (binding.MaxConnections <= 0 || binding.MaxConnectionsPerIp <= 0)
        {
            throw new ListenerApplyException("INVALID_RESOURCE_POLICY", "Connection limits must be greater than zero.");
        }
    }

    private static IPAddress ParseBindAddress(string bindAddress)
    {
        if (string.Equals(bindAddress, "localhost", StringComparison.OrdinalIgnoreCase))
        {
            return IPAddress.Loopback;
        }

        if (IPAddress.TryParse(bindAddress, out var address))
        {
            return address;
        }

        throw new ListenerApplyException("INVALID_BIND_ADDRESS", $"Bind address '{bindAddress}' is invalid.");
    }

    private static string ListenerKey(string bindAddress, int port, string transport) =>
        $"{bindAddress.Trim().ToLowerInvariant()}:{port}/{transport.Trim().ToLowerInvariant()}";

    private static string GetIp(EndPoint endpoint) => (endpoint as IPEndPoint)?.Address.ToString() ?? "0.0.0.0";

    private static int GetPort(EndPoint endpoint) => (endpoint as IPEndPoint)?.Port ?? 0;

    private static ListenerRuntimeStatus ToStatus(RuntimeListener runtime) => new(
        runtime.Binding.ListenerId,
        runtime.Instance.InstanceId,
        runtime.Binding.BindAddress,
        runtime.Binding.Port,
        runtime.Binding.Transport,
        runtime.State,
        Volatile.Read(ref runtime.ActiveConnections),
        runtime.AcceptedCount,
        runtime.ErrorCount,
        runtime.LastError);

    private async Task StopListenersAsync(
        IEnumerable<RuntimeListener> listeners,
        CancellationToken cancellationToken = default)
    {
        foreach (var runtime in listeners)
        {
            runtime.State = "Stopping";
            runtime.Cancellation.Cancel();
            runtime.Listener.Stop();
        }

        var loops = listeners.Select(runtime => runtime.AcceptLoop).OfType<Task>().ToArray();
        if (loops.Length > 0)
        {
            await Task.WhenAll(loops).WaitAsync(cancellationToken);
        }

        var sessions = listeners.SelectMany(runtime => runtime.Sessions.Keys).ToArray();
        if (sessions.Length > 0)
        {
            try { await Task.WhenAll(sessions).WaitAsync(TimeSpan.FromSeconds(5), cancellationToken); }
            catch (TimeoutException) { _logger.LogWarning("Listener session shutdown deadline exceeded: {ErrorCode}.", "SESSION_SHUTDOWN_TIMEOUT"); }
            catch (Exception) when (!cancellationToken.IsCancellationRequested)
            { _logger.LogError("Listener session shutdown failed: {ErrorCode}.", "SESSION_SHUTDOWN_FAILED"); }
        }

        foreach (var runtime in listeners)
        {
            runtime.Cancellation.Dispose();
        }
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(TcpListenerHost));
        }
    }

    private sealed class SequencedEventSink : IInteractionEventSink, ICredentialEvidenceSink
    {
        private readonly IInteractionEventSink _inner;
        private readonly IConnectionIdGenerator _idGenerator;
        private readonly ProtocolSessionContext _context;
        private long _sequence;

        public SequencedEventSink(IInteractionEventSink inner, IConnectionIdGenerator idGenerator, ProtocolSessionContext context, long initialSequence)
        {
            _inner = inner;
            _idGenerator = idGenerator;
            _context = context;
            _sequence = initialSequence;
        }

        public ValueTask<EventAppendResult> AppendAsync(InteractionEvent interactionEvent, CancellationToken cancellationToken = default)
        {
            var normalized = interactionEvent with
            {
                EventId = string.IsNullOrWhiteSpace(interactionEvent.EventId) ? _idGenerator.NewEventId() : interactionEvent.EventId,
                ConnectionId = _context.ConnectionId,
                Sequence = Interlocked.Increment(ref _sequence),
                ListenerId = _context.ListenerId,
                ServiceInstanceId = _context.ServiceInstanceId,
                AdapterKey = _context.AdapterKey,
                ProfileId = _context.ProfileId,
            };
            return _inner.AppendAsync(normalized, cancellationToken);
        }

        public ValueTask<string> StoreAsync(CredentialEvidence evidence, CancellationToken cancellationToken = default) =>
            _inner is ICredentialEvidenceSink sink
                ? sink.StoreAsync(evidence, cancellationToken)
                : ValueTask.FromException<string>(new AuthenticationRecordingException("CREDENTIAL_STORE_UNAVAILABLE"));
    }

    private sealed class ListenerApplyException : Exception
    {
        public ListenerApplyException(string code, string message) : base(message) => Code = code;
        public string Code { get; }
    }
}
