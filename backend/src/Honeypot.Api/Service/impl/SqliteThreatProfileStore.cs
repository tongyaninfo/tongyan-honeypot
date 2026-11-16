using System.Net;
using System.Text.Json;
using Honeypot.Api.Common;
using Honeypot.Api.Data;
using Honeypot.Api.Data.Models;
using Honeypot.Api.Options;
using Honeypot.Engine.Models;
using Honeypot.Engine.Service;
using Honeypot.Protocol.Abstractions.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Honeypot.Api.Service.impl;

public sealed class SqliteThreatProfileStore(IDbContextFactory<HoneypotDbContext> factory,
    IOptions<EventStorageOptions> options, TimeProvider time, IResourceIdGenerator ids) : IThreatProfileStore
{
    public ThreatIpProfile Apply(InteractionEvent interactionEvent) => Apply(interactionEvent, out _);

    public ThreatIpProfile Apply(InteractionEvent interactionEvent, out string? previousStatus)
    {
        interactionEvent = InteractionEventSanitizer.Sanitize(interactionEvent);
        using var db = factory.CreateDbContext();
        using var transaction = db.Database.BeginTransaction();
        var sourceIp = NormalizeIp(interactionEvent.SourceIp);
        var entity = db.Set<ThreatProfileEntity>().Find(sourceIp);
        var change = Update(db, entity, sourceIp, interactionEvent);
        db.SaveChanges();
        transaction.Commit();
        previousStatus = change.PreviousStatus;
        return change.Profile;
    }

    /// <summary>事件写入器去重后调用，事件、档案和凭据索引由调用方一次提交。</summary>
    public async Task<(ThreatIpProfile Profile, string? PreviousStatus)> ApplyAsync(HoneypotDbContext db,
        InteractionEvent interactionEvent, CancellationToken cancellationToken)
    {
        var sourceIp = NormalizeIp(interactionEvent.SourceIp);
        var entity = await db.Set<ThreatProfileEntity>().FindAsync([sourceIp], cancellationToken);
        return Update(db, entity, sourceIp, interactionEvent);
    }

    private (ThreatIpProfile Profile, string? PreviousStatus) Update(HoneypotDbContext db, ThreatProfileEntity? entity,
        string sourceIp, InteractionEvent interactionEvent)
    {
        var now = time.GetUtcNow();
        var isActive = entity is not null && entity.ExpiresAtUnixMs > now.ToUnixTimeMilliseconds();
        var profile = isActive ? ToProfile(entity!) : new ThreatIpProfile
        {
            ThreatId = $"threat-{ids.NewId()}",
            SourceIp = sourceIp,
            FirstSeenUtc = interactionEvent.OccurredAtUtc.ToUniversalTime(),
            LastSeenUtc = interactionEvent.OccurredAtUtc.ToUniversalTime(),
        };
        var previousStatus = isActive ? profile.Status : null;
        ThreatProfileAggregation.Apply(profile, interactionEvent, now.AddDays(options.Value.ThreatRetentionDays));
        if (entity is null)
        {
            entity = new() { SourceIp = sourceIp };
            db.Add(entity);
        }
        SetProfile(entity, profile);
        return (profile, previousStatus);
    }

    public IReadOnlyCollection<ThreatIpProfile> GetAll()
    {
        using var db = factory.CreateDbContext();
        return Active(db).OrderByDescending(item => item.LastSeenUtcTicks).ThenBy(item => item.SourceIp)
            .AsEnumerable().Select(ToProfile).ToArray();
    }

    public ThreatIpProfile? GetByIp(string sourceIp)
    {
        using var db = factory.CreateDbContext();
        var normalized = NormalizeIp(sourceIp);
        var entity = Active(db).SingleOrDefault(item => item.SourceIp == normalized);
        return entity is null ? null : ToProfile(entity);
    }

    public int Count()
    {
        using var db = factory.CreateDbContext();
        return Active(db).Count();
    }

    public IReadOnlySet<string> GetObservedSources(IReadOnlyCollection<string> sourceIps)
    {
        var observed = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (sourceIps.Count == 0) return observed;
        using var db = factory.CreateDbContext();
        var active = Active(db);
        // 按候选值走主键查找，分批保留 SQLite 的查询参数余量。
        foreach (var batch in sourceIps.Select(NormalizeIp).Distinct(StringComparer.OrdinalIgnoreCase).Chunk(256))
        {
            observed.UnionWith(active.Where(item => batch.Contains(item.SourceIp)).Select(item => item.SourceIp));
        }
        return sourceIps.Where(item => observed.Contains(NormalizeIp(item))).ToHashSet(StringComparer.OrdinalIgnoreCase);
    }

    public ThreatProfilePage Query(ThreatProfileQuery query)
    {
        using var db = factory.CreateDbContext();
        var matching = Active(db);
        if (query.SourceIp is { } sourceIp)
        {
            var ip = NormalizeIp(sourceIp);
            matching = matching.Where(item => item.SourceIp == ip);
        }
        if (query.MinimumScore > 0) matching = matching.Where(item => item.CurrentScore >= query.MinimumScore);
        if (query.Status is { } status) matching = matching.Where(item => item.Status == status);
        if (query.FromUtc is { } from) matching = matching.Where(item => item.LastSeenUtcTicks >= from.UtcTicks);
        if (query.ToUtc is { } to) matching = matching.Where(item => item.LastSeenUtcTicks < to.UtcTicks);

        var total = matching.Count();
        if (query.Offset >= total) return new([], total, query.PageNumber, query.BoundedPageSize);
        var ordered = query.Sort switch
        {
            ThreatProfileSort.Risk => matching.OrderByDescending(item => item.CurrentScore).ThenByDescending(item => item.LastSeenUtcTicks),
            ThreatProfileSort.RiskThenAuthenticationAttempts => matching.OrderByDescending(item => item.CurrentScore)
                .ThenByDescending(item => item.AuthenticationAttemptCount).ThenByDescending(item => item.LastSeenUtcTicks),
            _ => matching.OrderByDescending(item => item.LastSeenUtcTicks),
        };
        var items = ordered.ThenBy(item => item.SourceIp).Skip((int)query.Offset).Take(query.BoundedPageSize)
            .AsEnumerable().Select(ToProfile).ToArray();
        return new(items, total, query.PageNumber, query.BoundedPageSize);
    }

    private IQueryable<ThreatProfileEntity> Active(HoneypotDbContext db)
    {
        var now = time.GetUtcNow().ToUnixTimeMilliseconds();
        return db.Set<ThreatProfileEntity>().AsNoTracking().Where(item => item.ExpiresAtUnixMs > now);
    }

    private static string NormalizeIp(string sourceIp) => IPAddress.TryParse(sourceIp, out var address)
        ? (address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address).ToString()
        : sourceIp;

    private static ThreatIpProfile ToProfile(ThreatProfileEntity entity)
    {
        var profile = new ThreatIpProfile
        {
            ThreatId = entity.ThreatId,
            SourceIp = entity.SourceIp,
            FirstSeenUtc = new DateTimeOffset(entity.FirstSeenUtcTicks, TimeSpan.Zero),
            LastSeenUtc = new DateTimeOffset(entity.LastSeenUtcTicks, TimeSpan.Zero),
            CurrentScore = entity.CurrentScore,
            MaxScore = entity.MaxScore,
            ScoreVersion = entity.ScoreVersion,
            Status = entity.Status,
            AttemptCount = entity.AttemptCount,
            SessionCount = entity.SessionCount,
            ActiveSessionCount = entity.ActiveSessionCount,
            AuthenticationAttemptCount = entity.AuthenticationAttemptCount,
            ProtocolViolationCount = entity.ProtocolViolationCount,
            LastEventId = entity.LastEventId,
            LastReason = entity.LastReason,
            ExpiresAtUtc = DateTimeOffset.FromUnixTimeMilliseconds(entity.ExpiresAtUnixMs),
        };
        profile.ServicesTouched.UnionWith(JsonSerializer.Deserialize<string[]>(entity.ServicesJson)!);
        profile.PortsTouched.UnionWith(JsonSerializer.Deserialize<int[]>(entity.PortsJson)!);
        return profile;
    }

    private static void SetProfile(ThreatProfileEntity entity, ThreatIpProfile profile)
    {
        entity.ThreatId = profile.ThreatId;
        entity.FirstSeenUtcTicks = profile.FirstSeenUtc.UtcTicks;
        entity.LastSeenUtcTicks = profile.LastSeenUtc.UtcTicks;
        entity.ExpiresAtUnixMs = profile.ExpiresAtUtc!.Value.ToUnixTimeMilliseconds();
        entity.CurrentScore = profile.CurrentScore;
        entity.MaxScore = profile.MaxScore;
        entity.ScoreVersion = profile.ScoreVersion;
        entity.Status = profile.Status;
        entity.AttemptCount = profile.AttemptCount;
        entity.SessionCount = profile.SessionCount;
        entity.ActiveSessionCount = profile.ActiveSessionCount;
        entity.AuthenticationAttemptCount = profile.AuthenticationAttemptCount;
        entity.ProtocolViolationCount = profile.ProtocolViolationCount;
        entity.ServicesJson = JsonSerializer.Serialize(profile.ServicesTouched);
        entity.PortsJson = JsonSerializer.Serialize(profile.PortsTouched);
        entity.LastEventId = profile.LastEventId;
        entity.LastReason = profile.LastReason;
    }
}
