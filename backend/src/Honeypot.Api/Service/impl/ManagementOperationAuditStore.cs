using System.Threading.RateLimiting;
using Honeypot.Api.Data;
using Honeypot.Api.Data.Models;
using Honeypot.Api.Models;
using Honeypot.Api.Options;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Honeypot.Api.Service.impl;

public sealed class ManagementOperationAuditStore(
    IDbContextFactory<HoneypotDbContext> factory,
    IResourceIdGenerator ids,
    TimeProvider clock,
    IOptions<EventStorageOptions> options) : IDisposable
{
    // 匿名登录与初始化的失败审计各有独立额度，不影响成功操作。
    private readonly FixedWindowRateLimiter _deniedLoginAudit = CreatePublicAuditLimiter();
    private readonly FixedWindowRateLimiter _initializationAudit = CreatePublicAuditLimiter();

    private static FixedWindowRateLimiter CreatePublicAuditLimiter() => new(new FixedWindowRateLimiterOptions
    {
        PermitLimit = 12, Window = TimeSpan.FromMinutes(1), QueueLimit = 0, AutoReplenishment = true,
    });

    internal bool TryReserveDeniedLogin() => TryReserve(_deniedLoginAudit);
    internal bool TryReserveFailedInitialization() => TryReserve(_initializationAudit);

    private static bool TryReserve(FixedWindowRateLimiter limiter)
    {
        using var lease = limiter.AttemptAcquire(1);
        return lease.IsAcquired;
    }

    public Task<string> BeginAsync(string operation, string? actorUserId, CancellationToken cancellationToken) =>
        InsertAsync(operation, actorUserId, null, null, cancellationToken);

    internal Task<string> RecordCompletedAsync(string operation, string? actorUserId, string? resourceId, int status,
        CancellationToken cancellationToken) => InsertAsync(operation, actorUserId, resourceId, status, cancellationToken);

    private async Task<string> InsertAsync(string operation, string? actorUserId, string? resourceId, int? status,
        CancellationToken cancellationToken)
    {
        await using var db = await factory.CreateDbContextAsync(cancellationToken);
        db.Database.SetCommandTimeout(2);
        var row = new ManagementOperationAuditEntity
        {
            Id = ids.NewId(),
            OccurredAtUnixMs = clock.GetUtcNow().ToUnixTimeMilliseconds(),
            Operation = operation,
            ActorUserId = actorUserId,
            ResourceId = resourceId,
            HttpStatus = status,
        };
        db.Add(row);
        await db.SaveChangesAsync(cancellationToken);
        return row.Id;
    }

    public async Task CompleteAsync(string id, string? actorUserId, string? resourceId, int status, CancellationToken cancellationToken)
    {
        await using var db = await factory.CreateDbContextAsync(cancellationToken);
        db.Database.SetCommandTimeout(2);
        await db.Set<ManagementOperationAuditEntity>().Where(row => row.Id == id && row.HttpStatus == null)
            .ExecuteUpdateAsync(setters => setters.SetProperty(row => row.HttpStatus, status)
                .SetProperty(row => row.ResourceId, resourceId)
                .SetProperty(row => row.ActorUserId, row => actorUserId ?? row.ActorUserId), cancellationToken);
    }

    public async Task<(ManagementOperationAudit[] Items, int Total)> GetPageAsync(int page, int pageSize,
        CancellationToken cancellationToken)
    {
        var now = clock.GetUtcNow();
        var cutoff = now.AddDays(-options.Value.AuditRetentionDays).ToUnixTimeMilliseconds();
        var pendingAfter = now.AddMinutes(-2).ToUnixTimeMilliseconds();
        await using var db = await factory.CreateDbContextAsync(cancellationToken);
        db.Database.SetCommandTimeout(2);
        await db.Database.OpenConnectionAsync(cancellationToken);
        // 查询总数与当前页使用同一快照，避免并发写入时两者不一致。
        await using var transaction = ((SqliteConnection)db.Database.GetDbConnection()).BeginTransaction(deferred: true);
        await db.Database.UseTransactionAsync(transaction, cancellationToken);
        var query = db.Set<ManagementOperationAuditEntity>().AsNoTracking().Where(row => row.OccurredAtUnixMs >= cutoff);
        var total = await query.CountAsync(cancellationToken);
        var offset = ((long)page - 1) * pageSize;
        if (offset >= total) return ([], total);
        var rows = await query.OrderByDescending(row => row.OccurredAtUnixMs).ThenByDescending(row => row.Id)
            .Skip((int)offset).Take(pageSize).ToArrayAsync(cancellationToken);
        return (rows.Select(row => new ManagementOperationAudit(row.Id, DateTimeOffset.FromUnixTimeMilliseconds(row.OccurredAtUnixMs),
            row.Operation, row.ActorUserId, row.ResourceId,
            row.HttpStatus is not null ? "Completed" : row.OccurredAtUnixMs > pendingAfter ? "Pending" : "Unknown",
            row.HttpStatus)).ToArray(), total);
    }

    public void Dispose()
    {
        _deniedLoginAudit.Dispose();
        _initializationAudit.Dispose();
    }
}
