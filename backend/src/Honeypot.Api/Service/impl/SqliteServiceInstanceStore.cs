using System.Text.Json;
using Honeypot.Api.Data;
using Honeypot.Api.Data.Models;
using Honeypot.Protocol.Abstractions.Models;
using Microsoft.EntityFrameworkCore;

namespace Honeypot.Api.Service.impl;

/// <summary>
/// 使用 EF Core SQLite 持久化服务实例和监听端口。
/// 配置写入与端口集合替换在同一事务内完成，避免页面保存一半端口后留下不可启动配置。
/// </summary>
public sealed class SqliteServiceInstanceStore : IServiceInstanceStore
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly IDbContextFactory<HoneypotDbContext> _dbContextFactory;
    private readonly object _sync = new();

    public SqliteServiceInstanceStore(IDbContextFactory<HoneypotDbContext> dbContextFactory)
    {
        _dbContextFactory = dbContextFactory;
    }

    public ServiceInstance Upsert(ServiceInstance instance)
    {
        ArgumentNullException.ThrowIfNull(instance);
        lock (_sync)
        {
            using var db = _dbContextFactory.CreateDbContext();
            using var transaction = db.Database.BeginTransaction();
            var entity = db.ServiceInstances
                .Include(item => item.Bindings)
                .SingleOrDefault(item => item.InstanceId == instance.InstanceId);
            var now = DateTimeOffset.UtcNow;
            if (entity is null)
            {
                entity = ToEntity(instance, now, now);
                db.ServiceInstances.Add(entity);
            }
            else
            {
                entity.DisplayName = instance.DisplayName;
                entity.AdapterKey = instance.AdapterKey;
                entity.ProfileJson = JsonSerializer.Serialize(instance.Profile, JsonOptions);
                // Upsert 用于保存实例和端口配置。运行态、期望态和自动恢复策略由专用状态接口更新，
                // 不能因为前端只提交端口而被 JSON 默认值（Stopped/false）覆盖。
                entity.UpdatedAtUtc = now;
                var replacementBindings = instance.Bindings
                    .Select(binding => ToEntity(binding, instance.InstanceId))
                    .ToList();
                // 先提交删除，再添加新集合，避免同一 DbContext 中复用 ListenerId 时产生
                // “已有相同键实体被跟踪”的 EF Core 冲突。
                db.ListenerBindings.RemoveRange(entity.Bindings);
                db.SaveChanges();
                entity.Bindings.Clear();
                entity.Bindings = replacementBindings;
                db.ListenerBindings.AddRange(replacementBindings);
            }

            db.SaveChanges();
            transaction.Commit();
            return ToModel(entity);
        }
    }

    public IReadOnlyCollection<ServiceInstance> GetAll()
    {
        using var db = _dbContextFactory.CreateDbContext();
        return db.ServiceInstances
            .AsNoTracking()
            .Include(item => item.Bindings)
            .OrderBy(item => item.InstanceId)
            .AsEnumerable()
            .Select(ToModel)
            .ToArray();
    }

    public ServiceInstance? Get(string instanceId)
    {
        using var db = _dbContextFactory.CreateDbContext();
        var entity = db.ServiceInstances
            .AsNoTracking()
            .Include(item => item.Bindings)
            .SingleOrDefault(item => item.InstanceId == instanceId);
        return entity is null ? null : ToModel(entity);
    }

    public ServiceInstance? SetRuntimeState(string instanceId, string currentState, string? lastError = null)
    {
        lock (_sync)
        {
            using var db = _dbContextFactory.CreateDbContext();
            var entity = db.ServiceInstances
                .Include(item => item.Bindings)
                .SingleOrDefault(item => item.InstanceId == instanceId);
            if (entity is null)
            {
                return null;
            }

            entity.CurrentState = NormalizeState(currentState);
            entity.LastError = string.IsNullOrWhiteSpace(lastError) ? null : lastError.Trim();
            entity.UpdatedAtUtc = DateTimeOffset.UtcNow;
            db.SaveChanges();
            return ToModel(entity);
        }
    }

    public ServiceInstance? SetDesiredState(string instanceId, string desiredState, bool? autoStart = null)
    {
        lock (_sync)
        {
            using var db = _dbContextFactory.CreateDbContext();
            var entity = db.ServiceInstances
                .Include(item => item.Bindings)
                .SingleOrDefault(item => item.InstanceId == instanceId);
            if (entity is null)
            {
                return null;
            }

            entity.DesiredState = NormalizeState(desiredState);
            if (autoStart.HasValue)
            {
                entity.AutoStart = autoStart.Value;
            }

            entity.UpdatedAtUtc = DateTimeOffset.UtcNow;
            db.SaveChanges();
            return ToModel(entity);
        }
    }

    private static ServiceInstanceEntity ToEntity(ServiceInstance instance, DateTimeOffset createdAtUtc, DateTimeOffset updatedAtUtc) => new()
    {
        InstanceId = instance.InstanceId,
        DisplayName = instance.DisplayName,
        AdapterKey = instance.AdapterKey,
        ProfileJson = JsonSerializer.Serialize(instance.Profile, JsonOptions),
        DesiredState = NormalizeState(instance.DesiredState),
        AutoStart = instance.AutoStart,
        CurrentState = NormalizeState(instance.CurrentState),
        LastError = instance.LastError,
        CreatedAtUtc = createdAtUtc,
        UpdatedAtUtc = updatedAtUtc,
        Bindings = instance.Bindings.Select(binding => ToEntity(binding, instance.InstanceId)).ToList(),
    };

    private static ListenerBindingEntity ToEntity(ListenerBinding binding, string instanceId) => new()
    {
        ListenerId = binding.ListenerId,
        BindAddress = string.IsNullOrWhiteSpace(binding.BindAddress) ? "0.0.0.0" : binding.BindAddress,
        InstanceId = instanceId,
        Port = binding.Port,
        Transport = string.IsNullOrWhiteSpace(binding.Transport) ? "tcp" : binding.Transport,
        Enabled = binding.Enabled,
        MaxConnections = binding.MaxConnections,
        MaxConnectionsPerIp = binding.MaxConnectionsPerIp,
    };

    private static ServiceInstance ToModel(ServiceInstanceEntity entity)
    {
        var profile = JsonSerializer.Deserialize<ServiceProfile>(entity.ProfileJson, JsonOptions)
            ?? throw new InvalidOperationException($"INSTANCE_PROFILE_INVALID:{entity.InstanceId}");
        return new ServiceInstance
        {
            InstanceId = entity.InstanceId,
            DisplayName = entity.DisplayName,
            AdapterKey = entity.AdapterKey,
            Profile = profile,
            DesiredState = NormalizeState(entity.DesiredState),
            AutoStart = entity.AutoStart,
            CurrentState = NormalizeState(entity.CurrentState),
            LastError = entity.LastError,
            Bindings = entity.Bindings.Select(binding => new ListenerBinding
            {
                ListenerId = binding.ListenerId,
                BindAddress = binding.BindAddress,
                Port = binding.Port,
                Transport = binding.Transport,
                Enabled = binding.Enabled,
                MaxConnections = binding.MaxConnections,
                MaxConnectionsPerIp = binding.MaxConnectionsPerIp,
            }).ToArray(),
        };
    }

    private static string NormalizeState(string? state)
    {
        // 运行态来自监听编排器，不能把失败、启动中等状态静默折叠成 Stopped，
        // 否则前端会再次显示“启动”并允许重复启动，数据库也无法保留故障原因。
        return state?.Trim().ToLowerInvariant() switch
        {
            "starting" => "Starting",
            "running" => "Running",
            "stopping" => "Stopping",
            "failed" => "Failed",
            "degraded" => "Degraded",
            _ => "Stopped",
        };
    }
}
