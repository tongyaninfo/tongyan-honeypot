using System.Text.Json;
using Honeypot.Api.Common;
using Honeypot.Api.Service;
using Honeypot.Api.Service.impl;
using Honeypot.Protocol.Abstractions.Models;
using Honeypot.Protocol.Abstractions.Service;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace Honeypot.Runtime.Tests;

public sealed class McpBusinessOperationsTests
{
    [Fact]
    public async Task McpStartRechecksSavedBindingAfterRestSaveWithoutStartingUnapprovedListener()
    {
        var store = new InMemoryServiceInstanceStore();
        await using var listener = new RecordingListener();
        var operations = new ServiceInstanceOperations(store, listener, new NoopNotifier(), new ConfigurationBuilder().Build());
        var instance = SampleInstance("127.0.0.1", 12222);
        await operations.SaveAsync(instance, default);
        var fingerprint = McpInstanceScope.BindingFingerprint(instance);

        var updated = instance with { Bindings = [instance.Bindings[0] with { Port = 12223 }] };
        await operations.SaveAsync(updated, default);
        var denied = await operations.ExecuteAsync(instance.InstanceId, ServiceInstanceAction.Start, default, authorizedBindingFingerprint: fingerprint);
        Assert.Equal("INSTANCE_BINDINGS_CHANGED", denied.AccessDeniedCode);
        Assert.Empty(listener.Starts);

        var updatedGrant = McpInstanceScope.BindingFingerprint(updated);
        var authorized = await operations.ExecuteAsync(instance.InstanceId, ServiceInstanceAction.Start, default, authorizedBindingFingerprint: updatedGrant);
        Assert.True(authorized.ListenerResult!.Succeeded);
        Assert.Equal(12223, Assert.Single(Assert.Single(listener.Starts).Bindings).Port);

        var wildcard = SampleInstance("0.0.0.0", 12224);
        await operations.SaveAsync(wildcard, default);
        var wildcardGrant = McpInstanceScope.BindingFingerprint(wildcard);
        var unsafePolicy = await operations.ExecuteAsync(instance.InstanceId, ServiceInstanceAction.SetRestartPolicy, default, true, wildcardGrant);
        Assert.Equal("INSTANCE_BINDINGS_NOT_ISOLATED", unsafePolicy.AccessDeniedCode);
        Assert.False(store.Get(instance.InstanceId)!.AutoStart);
        Assert.Single(listener.Starts);
    }

    [Theory]
    [InlineData("queue_operation_report", "{\"requestId\":\"e083d860-7920-49c8-93ef-eef464405fbb\",\"recipients\":[\"other@example.invalid\"]}")]
    [InlineData("start_service_instance", "{\"instanceId\":\"test-instance\",\"bindAddress\":\"0.0.0.0\"}")]
    [InlineData("start_service_instance", "{\"instanceId\":\"allowed\",\"instanceId\":\"different\"}")]
    [InlineData("get_threat_source", "{\"sourceIp\":\"example.invalid\"}")]
    [InlineData("list_threat_events", "{\"fromUtc\":\"2026-11-11T09:30:00\"}")]
    public void ToolsRejectParametersOutsideTheirBusinessSchema(string name, string payload)
    {
        Assert.True(McpToolCatalog.TryGet(name, out var tool));
        Assert.False(McpToolArguments.TryCreate(tool.InputSchema, JsonSerializer.Deserialize<JsonElement>(payload), out _));
    }

    private static ServiceInstance SampleInstance(string address, int port) => new()
    {
        InstanceId = "test-instance",
        DisplayName = "Test",
        AdapterKey = "ssh",
        Profile = new() { ProfileId = "test-profile", AdapterKey = "ssh" },
        Bindings = [new() { ListenerId = "test-listener", BindAddress = address, Port = port }],
    };

    private sealed class RecordingListener : IListenerHost
    {
        public List<ServiceInstance> Starts { get; } = [];
        public IReadOnlyCollection<ListenerRuntimeStatus> GetStatuses() => [];
        public Task<ListenerApplyResult> ApplyAsync(ServiceInstance instance, CancellationToken cancellationToken = default)
        {
            Starts.Add(instance);
            return Task.FromResult(ListenerApplyResult.Applied());
        }
        public Task StopInstanceAsync(string instanceId, CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task StopAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    private sealed class NoopNotifier : IRealtimeUpdateNotifier
    {
        public Task PublishEventAsync(InteractionEvent interactionEvent, CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task PublishRuntimeAsync(IReadOnlyCollection<ListenerRuntimeStatus> statuses, CancellationToken cancellationToken = default) => Task.CompletedTask;
    }
}
