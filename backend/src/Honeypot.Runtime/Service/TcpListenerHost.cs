using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using Honeypot.Protocol.Abstractions.Models;
using Honeypot.Protocol.Abstractions.Service;
using Honeypot.Protocols.Common;
using Honeypot.Runtime.Common;
using Honeypot.Runtime.Models;
using Honeypot.Runtime.Options;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Honeypot.Runtime.Service;

/// <summary>
/// 单机 TCP 监听编排器。通过接纳检查的连接先记录，再交给协议适配器。
/// </summary>
public sealed class TcpListenerHost : IListenerHost
{
    private readonly object _sync = new();
    private readonly IProtocolAdapterRegistry _adapterRegistry;
    private readonly IInteractionEventSink _eventSink;
    private readonly IConnectionIdGenerator _idGenerator;
    private readonly ILogger<TcpListenerHost> _logger;
    private readonly ConnectionAdmission _admission;
    private readonly TimeSpan _acceptedEventTimeout;
    private readonly TimeProvider _clock;
    private Dictionary<string, RuntimeListener> _listeners = new(StringComparer.Ordinal);
    private bool _disposed;

    public TcpListenerHost(
        IProtocolAdapterRegistry adapterRegistry,
        IInteractionEventSink eventSink,
        IConnectionIdGenerator idGenerator,
        ILogger<TcpListenerHost> logger,
        IOptions<ConnectionAdmissionOptions>? admissionOptions = null,
        TimeProvider? timeProvider = null)
    {
        _adapterRegistry = adapterRegistry;
        _eventSink = eventSink;
        _idGenerator = idGenerator;
        _logger = logger;
        var options = admissionOptions?.Value ?? new ConnectionAdmissionOptions();
        if (!options.IsValid()) throw new ArgumentOutOfRangeException(nameof(admissionOptions), "连接接纳配置无效。");
        _clock = timeProvider ?? TimeProvider.System;
        _admission = new ConnectionAdmission(options, _clock);
        _acceptedEventTimeout = TimeSpan.FromSeconds(options.AcceptedEventTimeoutSeconds);
    }

    public IReadOnlyCollection<ListenerRuntimeStatus> GetStatuses()
    {
        lock (_sync)
        {
            return _listeners.Values.Select(ToStatus).ToArray();
        }
    }

    public IReadOnlyCollection<ActiveConnectionSnapshot> GetActiveConnections()
    {
        lock (_sync)
        {
            return _listeners.Values.SelectMany(listener => listener.ActiveConnectionDetails.Values).ToArray();
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

        instance = instance with { Profile = GetAdvertisementProfile(instance) };
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
                runtime.State == "Running" && runtime.Binding == binding && runtime.Instance.Profile == instance.Profile)))
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
                Interlocked.Increment(ref runtime.AcceptedCount);
                var acceptedAt = _clock.GetUtcNow();
                var remote = GetSocketEndpoint(client, remote: true);
                var local = GetSocketEndpoint(client, remote: false);
                var source = remote is null ? null : NormalizeAddress(remote.Address);
                var rejection = source is null ? "endpoint_unavailable" : runtime.Cancellation.IsCancellationRequested
                    ? "listener_stopping" : _admission.TryEnter(runtime, source);
                var first = new InteractionEvent
                {
                    EventId = _idGenerator.NewEventId(), ConnectionId = _idGenerator.NewConnectionId(), Sequence = 1,
                    EventType = rejection is null ? "ConnectionAccepted" : "ConnectionRejected",
                    OccurredAtUtc = acceptedAt, SourceIp = source?.ToString() ?? "", SourcePort = remote?.Port ?? 0,
                    DestinationIp = local is null ? runtime.Binding.BindAddress : NormalizeAddress(local.Address).ToString(),
                    DestinationPort = local?.Port ?? runtime.Binding.Port, Transport = "tcp",
                    ListenerId = runtime.Binding.ListenerId, ServiceInstanceId = runtime.Instance.InstanceId,
                    AdapterKey = runtime.Instance.AdapterKey, ProfileId = runtime.Instance.Profile.ProfileId,
                    Stage = rejection is null ? "accepted" : "admission", Outcome = rejection is null ? "recorded" : "rejected",
                    PayloadSummary = rejection, RiskDelta = rejection is null ? 1 : 0,
                };
                if (rejection is not null)
                {
                    Interlocked.Increment(ref runtime.RejectedCount);
                    client.Dispose();
                    // 串行等待留痕对 accept 施加背压，拒绝路径不创建协议会话或无界后台任务。
                    var closed = first with
                    {
                        EventId = _idGenerator.NewEventId(), Sequence = 2, EventType = "SessionClosed",
                        OccurredAtUtc = _clock.GetUtcNow(), Stage = "closed", Outcome = "admission_rejected",
                        CloseReason = SessionCloseReason.AdmissionRejected,
                    };
                    await RecordRejectedConnectionAsync(runtime, first, closed);
                    continue;
                }

                var endpoint = local ?? new IPEndPoint(ParseBindAddress(runtime.Binding.BindAddress), runtime.Binding.Port);
                var sessionTask = RunAdmittedConnectionAsync(runtime, client, remote!, endpoint, source!, first);
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

    private async Task RecordRejectedConnectionAsync(RuntimeListener runtime, InteractionEvent first, InteractionEvent closed)
    {
        // 真正完成 TCP accept 的拒绝也有独立 ID；停监听不能撤销已经发生的接纳和关闭。
        foreach (var item in new[] { first, closed })
        {
            try
            {
                var result = await RecordTransportEventAsync(item);
                if (!result.Recorded) WarnEventWriteFailure(runtime, result.Code);
            }
            catch (Exception)
            {
                WarnEventWriteFailure(runtime, "ADMISSION_EVENT_WRITE_FAILED");
            }
        }
    }

    private async Task RunAdmittedConnectionAsync(RuntimeListener runtime, TcpClient client, IPEndPoint remote,
        IPEndPoint local, IPAddress source, InteractionEvent first)
    {
        try
        {
            await HandleConnectionAsync(runtime, client, remote, local, first);
        }
        finally
        {
            // 即使创建会话或写关闭事件失败，也要释放共享的接纳额度。
            try { client.Dispose(); }
            finally
            {
                runtime.ActiveConnectionDetails.TryRemove(first.ConnectionId, out _);
                _admission.Exit(runtime, source);
            }
        }
    }

    private async Task HandleConnectionAsync(RuntimeListener runtime, TcpClient client, IPEndPoint remote,
        IPEndPoint local, InteractionEvent accepted)
    {
        var connectionId = accepted.ConnectionId;
        var remoteIp = accepted.SourceIp;
        var listenerStopping = runtime.Cancellation.Token;
        TcpHoneypotSession? session = null;
        var context = new ProtocolSessionContext(
            connectionId,
            runtime.Binding.ListenerId,
            runtime.Instance.InstanceId,
            runtime.Instance.AdapterKey,
            runtime.Instance.Profile.ProfileId,
            remote,
            local,
            accepted.OccurredAtUtc);

        var sequencedSink = new SequencedEventSink(_eventSink, _idGenerator, context, 1);
        SessionCloseReason? failureReason = null;
        var failureReported = false;
        try
        {
            // 活动连接跟随接纳额度的生命周期，即使事件仍在等待存储也可见。
            runtime.ActiveConnectionDetails[connectionId] = new(connectionId, accepted.OccurredAtUtc,
                accepted.SourceIp, accepted.SourcePort, accepted.AdapterKey, accepted.DestinationPort);
            var appendResult = await RecordTransportEventAsync(accepted);
            if (!appendResult.Recorded)
            {
                WarnEventWriteFailure(runtime, appendResult.Code);
                failureReported = true;
                failureReason = SessionCloseReason.StorageDegraded;
                return;
            }
            // 已经提交首条记录才访问协议流，对端在 accept 后立即复位仍然可追查。
            listenerStopping.ThrowIfCancellationRequested();
            try { session = new TcpHoneypotSession(client, connectionId, runtime.Instance.Profile.MaxSessionBytes); }
            catch (InvalidOperationException) when (!client.Connected)
            {
                failureReason = SessionCloseReason.ClientClosed;
                return;
            }
            if (!_adapterRegistry.TryGet(runtime.Instance.AdapterKey, out var adapter) || adapter is null)
            {
                await session.CloseAsync(SessionCloseReason.InternalError);
                return;
            }

            using var sessionTimeout = CancellationTokenSource.CreateLinkedTokenSource(listenerStopping);
            sessionTimeout.CancelAfter(runtime.Instance.Profile.IdleTimeout);
            await adapter.HandleAsync(session, context, runtime.Instance.Profile, sequencedSink, sessionTimeout.Token);
        }
        catch (OperationCanceledException) when (listenerStopping.IsCancellationRequested)
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
            failureReason = session?.ResourceLimitExceeded == true ? SessionCloseReason.ResourceLimitExceeded : SessionCloseReason.ClientClosed;
        }
        catch (AuthenticationRecordingException exception)
        {
            runtime.LastError = exception.Code;
            WarnEventWriteFailure(runtime, exception.Code);
            failureReported = true;
            failureReason = SessionCloseReason.StorageDegraded;
        }
        catch (Exception exception)
        {
            Interlocked.Increment(ref runtime.ErrorCount);
            // 协议输入不可信，异常消息和堆栈可能包含认证材料，仅暴露固定类型/错误码。
            runtime.LastError = exception.GetType().Name;
            _logger.LogError("Session {ConnectionId} failed on listener {ListenerId}: {ErrorCode}.", connectionId, runtime.Binding.ListenerId, runtime.LastError);
            failureReported = true;
            failureReason = SessionCloseReason.InternalError;
        }
        finally
        {
            var reason = failureReason ?? (session?.ResourceLimitExceeded == true ? SessionCloseReason.ResourceLimitExceeded
                : session?.CloseReason ?? SessionCloseReason.AdapterCompleted);
            if (!failureReported && reason == SessionCloseReason.StorageDegraded)
            {
                WarnEventWriteFailure(runtime, "SESSION_STORAGE_DEGRADED");
                failureReported = true;
            }
            else if (!failureReported && reason == SessionCloseReason.InternalError)
            {
                _logger.LogError("Session {ConnectionId} closed on listener {ListenerId}: {ErrorCode}.",
                    connectionId, runtime.Binding.ListenerId, "SESSION_INTERNAL_ERROR");
            }
            try
            {
                if (session is null) client.Dispose();
                else await session.CloseAsync(reason);
            }
            catch (Exception)
            {
                // 资源释放失败单独诊断，不能跳过连接计数回收或伪造正常结束。
                reason = SessionCloseReason.InternalError;
                _logger.LogError("Session {ConnectionId} disposal failed: {ErrorCode}.", connectionId, "SESSION_DISPOSE_FAILED");
            }
            if (reason == SessionCloseReason.AdapterCompleted && session?.CloseReason is { } observedReason)
                reason = observedReason;
            // 最终事件只在这里生成一次，覆盖所有早退/异常分支；宿主停止的令牌不能取消关闭留痕。
            using var finalDeadline = new CancellationTokenSource(TimeSpan.FromSeconds(2));
            try
            {
                if (session?.ResourceLimitExceeded == true)
                    await sequencedSink.AppendAsync(new InteractionEvent
                    {
                        EventId = _idGenerator.NewEventId(), ConnectionId = connectionId,
                        EventType = "ResourceLimitExceeded", OccurredAtUtc = _clock.GetUtcNow(),
                        SourceIp = remoteIp, SourcePort = remote.Port,
                        DestinationIp = accepted.DestinationIp, DestinationPort = accepted.DestinationPort,
                        ListenerId = context.ListenerId, ServiceInstanceId = context.ServiceInstanceId,
                        AdapterKey = context.AdapterKey, ProfileId = context.ProfileId,
                        Stage = "transport", Outcome = "resource_limit", PayloadSummary = "Session byte limit exceeded",
                    }, finalDeadline.Token).AsTask().WaitAsync(finalDeadline.Token);
            }
            catch (Exception)
            {
                WarnEventWriteFailure(runtime, "SESSION_LIMIT_RECORD_FAILED");
            }
            using var closeDeadline = new CancellationTokenSource(TimeSpan.FromSeconds(2));
            try
            {
                var closed = new InteractionEvent
                {
                    EventId = _idGenerator.NewEventId(), ConnectionId = connectionId, EventType = "SessionClosed",
                    OccurredAtUtc = _clock.GetUtcNow(), SourceIp = remoteIp, SourcePort = remote.Port,
                    DestinationIp = accepted.DestinationIp, DestinationPort = accepted.DestinationPort,
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
                if (!closedResult.Recorded) WarnEventWriteFailure(runtime, closedResult.Code);
            }
            catch (Exception)
            {
                // 关闭事件有独立写入结果，即使接纳或认证已失败，也要计数。
                WarnEventWriteFailure(runtime, "SESSION_CLOSE_RECORD_FAILED");
            }
        }
    }

    private async Task<EventAppendResult> RecordTransportEventAsync(InteractionEvent item)
    {
        using var deadline = new CancellationTokenSource(_acceptedEventTimeout);
        try { return await _eventSink.AppendAsync(item, deadline.Token).AsTask().WaitAsync(deadline.Token); }
        catch (OperationCanceledException) when (deadline.IsCancellationRequested)
        { return EventAppendResult.DegradedResult("CONNECTION_EVENT_TIMEOUT", "连接事件写入超时。"); }
    }

    private void WarnEventWriteFailure(RuntimeListener runtime, string code)
    {
        var failures = Interlocked.Increment(ref runtime.EventWriteFailureCount);
        var lastWarning = Volatile.Read(ref runtime.LastEventWriteWarningTimestamp);
        var now = _clock.GetTimestamp();
        // 存储故障持续时只更新计数，避免每条连接再产生错误日志和 Syslog 外发。
        if (lastWarning == long.MinValue || _clock.GetElapsedTime(lastWarning, now) >= TimeSpan.FromSeconds(30))
        {
            if (Interlocked.CompareExchange(ref runtime.LastEventWriteWarningTimestamp, now, lastWarning) == lastWarning)
                _logger.LogWarning("Listener {ListenerId} event could not be recorded: {ErrorCode}. FailureCount={FailureCount}",
                    runtime.Binding.ListenerId, code, failures);
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

    private static IPEndPoint? GetSocketEndpoint(TcpClient client, bool remote)
    {
        try { return (remote ? client.Client.RemoteEndPoint : client.Client.LocalEndPoint) as IPEndPoint; }
        catch (SocketException) { return null; }
    }

    private static IPAddress NormalizeAddress(IPAddress address) => address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;

    private static ServiceProfile GetAdvertisementProfile(ServiceInstance instance)
    {
        var profile = instance.Profile;
        // 只比较本机标识和已经绑定的地址，避免为了仿真人格执行 DNS 查询。
        var defaults = ServiceAdapterDefaults.For(profile.AdapterKey);
        var machineName = Environment.MachineName.TrimEnd('.');
        var safeHost = defaults.HostName.Equals(machineName, StringComparison.OrdinalIgnoreCase)
            ? "simulated-service.example.test" : defaults.HostName;
        return profile with
        {
            AdvertisedHostName = IsHostIdentity(ProtocolFingerprint.HostName(profile), machineName, instance.Bindings)
                ? safeHost : profile.AdvertisedHostName,
            AdvertisedProduct = IsHostIdentity(profile.AdvertisedProduct, defaults.Product, machineName, instance.Bindings)
                ? defaults.Product : profile.AdvertisedProduct,
            AdvertisedVersion = IsHostIdentity(profile.AdvertisedVersion, defaults.ProductVersion, machineName, instance.Bindings)
                ? defaults.ProductVersion : profile.AdvertisedVersion,
        };
    }

    private static bool IsHostIdentity(string? configured, string simulatedDefault, string machineName, IReadOnlyList<ListenerBinding> bindings)
    {
        if (string.Equals(configured?.Trim(), simulatedDefault, StringComparison.OrdinalIgnoreCase)) return false;
        return IsHostIdentity(configured, machineName, bindings);
    }

    private static bool IsHostIdentity(string? configured, string machineName, IReadOnlyList<ListenerBinding> bindings)
    {
        var candidate = configured?.Trim().TrimEnd('.');
        if (string.IsNullOrEmpty(candidate) || candidate.Equals("localhost", StringComparison.OrdinalIgnoreCase)) return false;
        if (candidate.Equals(machineName, StringComparison.OrdinalIgnoreCase)) return true;
        if (!IPAddress.TryParse(candidate, out var requestedAddress)) return false;

        requestedAddress = NormalizeAddress(requestedAddress);
        if (IPAddress.IsLoopback(requestedAddress)) return false;
        if (bindings.Any(binding => IPAddress.TryParse(binding.BindAddress, out var bindingAddress) &&
            NormalizeAddress(bindingAddress).Equals(requestedAddress))) return true;

        try
        {
            return NetworkInterface.GetAllNetworkInterfaces().SelectMany(network => network.GetIPProperties().UnicastAddresses)
                .Any(address => NormalizeAddress(address.Address).Equals(requestedAddress));
        }
        catch (Exception error) when (error is NetworkInformationException or SocketException or PlatformNotSupportedException)
        {
            return true;
        }
    }

    private static ListenerRuntimeStatus ToStatus(RuntimeListener runtime) => new(
        runtime.Binding.ListenerId,
        runtime.Instance.InstanceId,
        runtime.Binding.BindAddress,
        runtime.Binding.Port,
        runtime.Binding.Transport,
        runtime.State,
        Volatile.Read(ref runtime.ActiveConnections),
        Volatile.Read(ref runtime.AcceptedCount),
        runtime.ErrorCount,
        runtime.LastError)
    {
        RejectedCount = Volatile.Read(ref runtime.RejectedCount),
        EventWriteFailureCount = Volatile.Read(ref runtime.EventWriteFailureCount),
    };

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

    private sealed class SequencedEventSink : IInteractionEventSink, ICredentialEvidenceSink, ICredentialEventSink
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

        public ValueTask<EventAppendResult> AppendAsync(InteractionEvent interactionEvent, CancellationToken cancellationToken = default) =>
            _inner.AppendAsync(Sequence(interactionEvent), cancellationToken);

        public ValueTask<CredentialEventResult> AppendWithEvidenceAsync(InteractionEvent item, CredentialEvidence evidence, CancellationToken cancellationToken = default) =>
            CredentialEventRecording.AppendAsync(_inner, Sequence(item), evidence, cancellationToken);

        private InteractionEvent Sequence(InteractionEvent interactionEvent) =>
            interactionEvent with
            {
                EventId = string.IsNullOrWhiteSpace(interactionEvent.EventId) ? _idGenerator.NewEventId() : interactionEvent.EventId,
                ConnectionId = _context.ConnectionId,
                Sequence = Interlocked.Increment(ref _sequence),
                ListenerId = _context.ListenerId,
                ServiceInstanceId = _context.ServiceInstanceId,
                AdapterKey = _context.AdapterKey,
                ProfileId = _context.ProfileId,
            };

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
