using Honeypot.Api.Data.Models;
using Microsoft.EntityFrameworkCore;

namespace Honeypot.Api.Data;

/// <summary>
/// Honeypot 本地配置、报告元数据与邮件任务数据库，不保存认证证据原文。
/// </summary>
public sealed class HoneypotDbContext : DbContext
{
    public HoneypotDbContext(DbContextOptions<HoneypotDbContext> options) : base(options)
    {
    }

    public DbSet<ServiceInstanceEntity> ServiceInstances => Set<ServiceInstanceEntity>();
    public DbSet<ListenerBindingEntity> ListenerBindings => Set<ListenerBindingEntity>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        // 各业务实体在独立配置类中定义，报告与邮件均复用现有 SQLite 和迁移入口。
        modelBuilder.ApplyConfigurationsFromAssembly(typeof(HoneypotDbContext).Assembly);

        modelBuilder.Entity<ServiceInstanceEntity>(entity =>
        {
            entity.ToTable("service_instances");
            entity.HasKey(item => item.InstanceId);
            entity.Property(item => item.InstanceId).HasMaxLength(128).IsRequired();
            entity.Property(item => item.DisplayName).HasMaxLength(256).IsRequired();
            entity.Property(item => item.AdapterKey).HasMaxLength(64).IsRequired();
            entity.Property(item => item.ProfileJson).IsRequired();
            entity.Property(item => item.DesiredState).HasMaxLength(32).IsRequired();
            entity.Property(item => item.CurrentState).HasMaxLength(32).IsRequired();
            entity.Property(item => item.LastError).HasMaxLength(2000);
            entity.HasMany(item => item.Bindings)
                .WithOne(item => item.Instance)
                .HasForeignKey(item => item.InstanceId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<ListenerBindingEntity>(entity =>
        {
            entity.ToTable("listener_bindings");
            entity.HasKey(item => item.ListenerId);
            entity.Property(item => item.ListenerId).HasMaxLength(128).IsRequired();
            entity.Property(item => item.InstanceId).HasMaxLength(128).IsRequired();
            entity.Property(item => item.BindAddress).HasMaxLength(128).IsRequired();
            entity.Property(item => item.Transport).HasMaxLength(16).IsRequired();
            entity.HasIndex(item => new { item.BindAddress, item.Port, item.Transport }).IsUnique();
        });
    }
}
