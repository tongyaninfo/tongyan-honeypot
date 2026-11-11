using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using Honeypot.Protocol.Abstractions.Models;
using Honeypot.Protocol.Abstractions.Service;

namespace Honeypot.Runtime.Service.impl;

/// <summary>
/// 单机 TCP 监听编排器。它先记录 ConnectionAccepted，再把会话交给协议适配器。
/// </summary>
public sealed class TcpListenerHost : IListenerHost
{
    private sealed class BindingRuntime
    {
        public required ServiceInstance Instance { get; init; }
        public required ListenerBinding Binding { get; init; }
        public required TcpListener Listener { get; init; }
        public required CancellationTokenSource Cancellation { get; init; }
        public long AcceptedCount;
        public long ErrorCount;
        public int ActiveConnections;
        public string State { get; set; } = "Starting";
        public string? LastError { get; set; }
    }

    private readonly IProtocolAdapterRegistry _registry;
    private readonly IInteractionEventSink _eventSink;
    private readonly IConnectionIdGenerator _idGenerator;
    private readonly ConcurrentDictionary<string, BindingRuntime> _bindings = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, Task> _acceptLoops = new(StringComparer.OrdinalIgnoreCase);
    private readonly SemaphoreSlim _applyLock = new(1, 1);
    private int _stopped;

    public TcpListenerHost(
        IProtocolAdapterRegistry registry,
        IInteractionEventSink eventSink,
        IConnectionIdGenerator idGenerator)
    {
        _registry = registry;
        _eventSink = eventSink;
        _idGenerator = idGenerator;
    }

    public IReadOnlyCollection<ListenerRuntimeStatus> GetStatuses() => _bindings.Values
        .OrderBy(item => item.Binding.ListenerId)
        .Select(item => new ListenerRuntimeStatus(
            item.Binding.ListenerId,
            item.Instance.InstanceId,
            item.Binding.BindAddress,
            item.Binding.Port,
            item.Binding.Transport,
            item.State,
            item.ActiveConnections,
            item.AcceptedCount,
            item.ErrorCount,
            item.LastError))
        .ToArray();

    public async Task<ListenerApplyResult> ApplyAsync(ServiceInstance instance, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(instance);
        await _applyLock.WaitAsync(cancellationToken);
        try
        {
            if (instance.Bindings.Any(binding => !binding.Enabled))
            {
                return ListenerApplyResult.Failed("VALIDATION_ERROR", "disabled bindings must be removed before apply");
            }

            if (!_registry.TryGet(instance.AdapterKey, out var adapter) || adapter is null)
            {
                return ListenerApplyResult.Failed("ADAPTER_UNAVAILABLE", $"Adapter '{instance.AdapterKey}' is not registered.");
            }

            var validation = await adapter.ValidateAsync(instance.Profile, cancellationToken);
            if (!validation.IsValid)
            {
                return ListenerApplyResult.Failed(validation.Code, validation.Message);
            }

            var duplicate = instance.Bindings
                .GroupBy(binding => $"{binding.BindAddress}:{binding.Port}/{binding.Transport}", StringComparer.OrdinalIgnoreCase)
                .FirstOrDefault(group => group.Count() > 1);
            if (duplicate is not null)
            {
                return ListenerApplyResult.Failed("PORT_CONFLICT", $"Duplicate binding '{duplicate.Key}'.");
            }

            await StopBindingsAsync(instance.InstanceId, cancellationToken);
            foreach (var binding in instance.Bindings.Where(item => item.Enabled))
            {
                if (!string.Equals(binding.Transport, "tcp", StringComparison.OrdinalIgnoreCase))
                {
                    return ListenerApplyResult.Failed("UNSUPPORTED_TRANSPORT", $"Transport '{binding.Transport}' is not supported.");
                }

                if (binding.Port is < 1 or > 65535)
                {
                    return ListenerApplyResult.Failed("INVALID_PORT", $"Port '{binding.Port}' is outside 1-65535.");
                }

                if (_bindings.Values.Any(existing =>
                        !existing.Instance.InstanceId.Equals(instance.InstanceId, StringComparison.OrdinalIgnoreCase) &&
                        existing.Binding.BindAddress.Equals(binding.BindAddress, StringComparison.OrdinalIgnoreCase) &&
                        existing.Binding.Port == binding.Port &&
                        existing.Binding.Transport.Equals(binding.Transport, StringComparison.OrdinalIgnoreCase)))
                {
                    return ListenerApplyResult.Failed("PORT_CONFLICT", $"Binding '{binding.BindAddress}:{binding.Port}' is already in use.");
                }

                var address = IPAddress.Parse(binding.BindAddress);
                var listener = new TcpListener(address, binding.Port);
                try
                {
                    listener.Start();
                }
                catch (Exception ex) when (ex is SocketException or InvalidOperationException)
                {
                    listener.Stop();
                    await StopBindingsAsync(instance.InstanceId, cancellationToken);
                    return ListenerApplyResult.Failed("BIND_FAILED", ex.Message);
                }

                var runtime = new BindingRuntime
                {
                    Instance = instance,
                    Binding = binding,
                    Listener = listener,
                    Cancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken),
                    State = "Running",
                };
                _bindings[binding.ListenerId] = runtime;
                _acceptLoops[binding.ListenerId] = AcceptLoopAsync(runtime);
            }

            return ListenerApplyResult.Applied();
        }
        finally
        {
            _applyLock.Release();
        }
    }

    public async Task StopInstanceAsync(string instanceId, CancellationToken cancellationToken = default)
    {
        var selected = _bindings.Values
            .Where(runtime => runtime.Instance.InstanceId.Equals(instanceId, StringComparison.OrdinalIgnoreCase))
            .ToArray();
        foreach (var runtime in selected)
        {
            runtime.Cancellation.Cancel();
            runtime.Listener.Stop();
            _bindings.TryRemove(runtime.Binding.ListenerId, out _);
        }

        foreach (var runtime in selected)
        {
            if (_acceptLoops.TryRemove(runtime.Binding.ListenerId, out var loop))
            {
                await loop.WaitAsync(cancellationToken);
            }
        }
    }

    public async Task StopAsync(CancellationToken cancellationToken = default)
    {
        if (Interlocked.Exchange(ref _stopped, 1) == 1)
        {
            return;
        }

        await _applyLock.WaitAsync(cancellationToken);
        try
        {
            foreach (var runtime in _bindings.Values)
            {
                runtime.State = "Stopping";
                runtime.Cancellation.Cancel();
                runtime.Listener.Stop();
            }

            await Task.WhenAll(_acceptLoops.Values);
            _bindings.Clear();
            _acceptLoops.Clear();
        }
        finally
        {
            _applyLock.Release();
        }
    }

    public async ValueTask DisposeAsync() => await StopAsync();

    private async Task AcceptLoopAsync(BindingRuntime runtime)
    {
        while (!runtime.Cancellation.IsCancellationRequested)
        {
            TcpClient client;
            try
            {
                client = await runtime.Listener.AcceptTcpClientAsync(runtime.Cancellation.Token);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (ObjectDisposedException)
            {
                break;
            }
            catch (Exception ex)
            {
                runtime.ErrorCount++;
                runtime.LastError = ex.Message;
                break;
            }

            runtime.AcceptedCount++;
            _ = HandleConnectionAsync(runtime, client);
        }

        runtime.State = runtime.Cancellation.IsCancellationRequested ? "Stopped" : "Failed";
    }

    private async Task HandleConnectionAsync(BindingRuntime runtime, TcpClient client)
    {
        if (runtime.ActiveConnections >= runtime.Binding.MaxConnections)
        {
            client.Dispose();
            runtime.ErrorCount++;
            return;
        }

        Interlocked.Increment(ref runtime.ActiveConnections);
        var connectionId = _idGenerator.NewConnectionId();
        var session = new TcpHoneypotSession(connectionId, client);
        var adapter = _registry.GetRequired(runtime.Instance.AdapterKey);
        var remote = session.RemoteEndPoint as IPEndPoint;
        var local = session.LocalEndPoint as IPEndPoint;
        var acceptedAt = DateTimeOffset.UtcNow;
        var context = new ProtocolSessionContext(
            connectionId,
            runtime.Binding.ListenerId,
            runtime.Instance.InstanceId,
            runtime.Instance.AdapterKey,
            runtime.Instance.Profile.ProfileId,
            session.RemoteEndPoint,
            session.LocalEndPoint,
            acceptedAt);
        var sequencedSink = new SequencedEventSink(_eventSink, _idGenerator, context, runtime.Instance.Profile.ProfileId, 1);

        try
        {
            var accepted = new InteractionEvent
            {
                EventId = _idGenerator.NewEventId(),
                ConnectionId = connectionId,
                Sequence = 1,
                EventType = "ConnectionAccepted",
                OccurredAtUtc = acceptedAt,
                SourceIp = remote?.Address.ToString() ?? "unknown",
                SourcePort = remote?.Port ?? 0,
                DestinationIp = local?.Address.ToString() ?? "unknown",
                DestinationPort = local?.Port ?? runtime.Binding.Port,
                ListenerId = runtime.Binding.ListenerId,
                ServiceInstanceId = runtime.Instance.InstanceId,
                AdapterKey = runtime.Instance.AdapterKey,
                ProfileId = runtime.Instance.Profile.ProfileId,
                Stage = "accepted",
                Outcome = "recorded",
                RiskDelta = 1,
            };
            var appendResult = await _eventSink.AppendAsync(accepted, runtime.Cancellation.Token);
            if (!appendResult.Recorded)
            {
                await session.CloseAsync(SessionCloseReason.StorageDegraded);
                return;
            }

            await adapter.HandleAsync(session, context, runtime.Instance.Profile, sequencedSink, runtime.Cancellation.Token);
            await sequencedSink.AppendAsync(new InteractionEvent
            {
                EventId = _idGenerator.NewEventId(),
                ConnectionId = connectionId,
                EventType = "SessionClosed",
                OccurredAtUtc = DateTimeOffset.UtcNow,
                SourceIp = remote?.Address.ToString() ?? "unknown",
                SourcePort = remote?.Port ?? 0,
                DestinationIp = local?.Address.ToString() ?? "unknown",
                DestinationPort = local?.Port ?? runtime.Binding.Port,
                ListenerId = runtime.Binding.ListenerId,
                ServiceInstanceId = runtime.Instance.InstanceId,
                AdapterKey = runtime.Instance.AdapterKey,
                ProfileId = runtime.Instance.Profile.ProfileId,
                Stage = "closed",
                Outcome = "completed",
            }, runtime.Cancellation.Token);
        }
        catch (OperationCanceledException)
        {
            await session.CloseAsync(SessionCloseReason.ListenerStopping);
        }
        catch (Exception ex)
        {
            runtime.ErrorCount++;
            runtime.LastError = ex.Message;
            await session.CloseAsync(SessionCloseReason.InternalError);
        }
        finally
        {
            await session.DisposeAsync();
            Interlocked.Decrement(ref runtime.ActiveConnections);
        }
    }

    private async Task StopBindingsAsync(string instanceId, CancellationToken cancellationToken)
    {
        var toStop = _bindings.Values.Where(item => item.Instance.InstanceId.Equals(instanceId, StringComparison.OrdinalIgnoreCase)).ToArray();
        foreach (var runtime in toStop)
        {
            runtime.Cancellation.Cancel();
            runtime.Listener.Stop();
            _bindings.TryRemove(runtime.Binding.ListenerId, out _);
        }

        foreach (var runtime in toStop)
        {
            if (_acceptLoops.TryRemove(runtime.Binding.ListenerId, out var loop))
            {
                await loop.WaitAsync(cancellationToken);
            }
        }
    }

    private sealed class SequencedEventSink : IInteractionEventSink
    {
        private readonly IInteractionEventSink _inner;
        private readonly IConnectionIdGenerator _idGenerator;
        private readonly ProtocolSessionContext _context;
        private long _sequence;

        public SequencedEventSink(IInteractionEventSink inner, IConnectionIdGenerator idGenerator, ProtocolSessionContext context, string profileId, long initialSequence)
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
    }
}
