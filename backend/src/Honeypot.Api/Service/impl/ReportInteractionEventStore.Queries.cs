using Honeypot.Api.Common;
using Honeypot.Api.Data;
using Honeypot.Api.Data.Models;
using Honeypot.Api.Models;
using Honeypot.Protocol.Abstractions.Models;
using Microsoft.EntityFrameworkCore;

namespace Honeypot.Api.Service.impl;

public sealed partial class ReportInteractionEventStore
{
    public IReadOnlyCollection<InteractionEvent> GetAll()
    {
        using var db = OpenReadContext();
        var now = _time.GetUtcNow();
        var recent = now.AddHours(-_options.MemoryRetentionHours).ToUnixTimeMilliseconds();
        // 总览与地图只取有上限的近期快照。数据库历史通过独立分页接口查询。
        return OrderForList(Active(db, now).Where(item => item.ReceivedAtUnixMs > recent)
            .OrderByDescending(item => item.ReceivedAtUnixMs).ThenByDescending(item => item.OccurredAtUtcTicks)
            .ThenByDescending(item => item.Sequence).Take(_options.MemoryEventCapacity))
            .Select(item => item.EventJson).AsEnumerable().Select(InteractionEventEntity.Read).ToArray();
    }

    public IReadOnlyCollection<InteractionEvent> GetByConnectionId(string connectionId)
    {
        using var db = OpenReadContext();
        return Active(db, _time.GetUtcNow()).Where(item => item.ConnectionId == connectionId)
            .OrderBy(item => item.Sequence).ThenBy(item => item.OccurredAtUtcTicks).ThenBy(item => item.EventId)
            .Select(item => item.EventJson).AsEnumerable().Select(InteractionEventEntity.Read).ToArray();
    }

    public QueryPageResult<InteractionEvent> ReadEvents(InteractionEventQuery query)
    {
        using var db = OpenReadContext();
        var filtered = FilterEvent(FilterConnection(Active(db, _time.GetUtcNow()), query), query);
        var (page, size, offset) = QueryPage.Bounds(query.Page, query.PageSize);
        var total = filtered.Count();
        var items = offset < total ? OrderForList(filtered).Skip((int)offset).Take(size)
            .Select(item => item.EventJson).AsEnumerable().Select(InteractionEventEntity.Read).ToArray() : [];
        return new(items, total, page, size);
    }

    public QueryPageResult<RealtimeInteractionEvent> ReadActivities(InteractionEventQuery query)
    {
        using var db = OpenReadContext();
        var connectionSteps = FilterConnection(Active(db, _time.GetUtcNow()), query);
        // 每次认证都显示；没有认证时按共用优先级取一个代表步骤，再应用事件类型和时间筛选。
        var representatives = connectionSteps.Where(item => item.ActivityPriority == InteractionActivityProjection.Authentication ||
            item.EventId == connectionSteps.Where(step => step.ConnectionId == item.ConnectionId)
                .OrderByDescending(step => step.ActivityPriority)
                .ThenBy(step => step.ActivityPriority == InteractionActivityProjection.Accepted ? step.Sequence : 0L)
                .ThenByDescending(step => step.Sequence)
                .ThenBy(step => step.ActivityPriority == InteractionActivityProjection.Accepted ? step.OccurredAtUtcTicks : 0L)
                .ThenByDescending(step => step.OccurredAtUtcTicks)
                .ThenBy(step => step.EventId).Select(step => step.EventId).First());
        var filtered = FilterEvent(representatives, query);
        var (page, size, offset) = QueryPage.Bounds(query.Page, query.PageSize);
        // 没有步骤筛选时，每个连接贡献全部认证活动，或在无认证时贡献一个代表步骤。
        // 按原 ConnectionId 列的 NOCASE 规则分组，避免为了计数逐行查找代表步骤。
        var total = string.IsNullOrWhiteSpace(query.EventType) && query.FromUtc is null && query.ToUtc is null
            ? connectionSteps.GroupBy(step => step.ConnectionId)
                .Select(connection => connection.Count(step => step.ActivityPriority == InteractionActivityProjection.Authentication))
                .Sum(activities => activities == 0 ? 1 : activities)
            : filtered.Count();
        var items = offset < total ? OrderForList(filtered).Skip((int)offset).Take(size).Select(item => new
            {
                item.EventJson,
                EventCount = connectionSteps.Count(step => step.ConnectionId == item.ConnectionId),
            }).AsEnumerable().Select(item => RealtimeInteractionEvent.From(InteractionEventEntity.Read(item.EventJson))
                with { EventCount = item.EventCount }).ToArray() : [];
        return new(items, total, page, size);
    }

    private HoneypotDbContext OpenReadContext()
    {
        var db = factory.CreateDbContext();
        db.Database.SetCommandTimeout(2);
        return db;
    }

    private IQueryable<InteractionEventEntity> Active(HoneypotDbContext db, DateTimeOffset now)
    {
        var cutoff = now.AddDays(-_options.DetailRetentionDays).ToUnixTimeMilliseconds();
        return db.Set<InteractionEventEntity>().AsNoTracking().Where(item => item.ReceivedAtUnixMs > cutoff);
    }

    private static IQueryable<InteractionEventEntity> FilterConnection(IQueryable<InteractionEventEntity> source, InteractionEventQuery query)
    {
        if (query.ConnectionIds is { } ids)
        {
            var keys = ids.ToArray();
            source = source.Where(item => keys.Contains(item.ConnectionId) && keys.Contains(EF.Functions.Collate(item.ConnectionId, "BINARY")));
        }
        if (!string.IsNullOrWhiteSpace(query.SourceIp)) source = source.Where(item => item.SourceIp == query.SourceIp);
        if (!string.IsNullOrWhiteSpace(query.AdapterKey)) source = source.Where(item => item.AdapterKey == query.AdapterKey);
        if (query.DestinationPort is { } port) source = source.Where(item => item.DestinationPort == port);
        return source;
    }

    private static IQueryable<InteractionEventEntity> FilterEvent(IQueryable<InteractionEventEntity> source, InteractionEventQuery query)
    {
        if (!string.IsNullOrWhiteSpace(query.EventType)) source = source.Where(item => item.EventType == query.EventType);
        if (query.FromUtc is { } from) source = source.Where(item => item.OccurredAtUtcTicks >= from.UtcTicks);
        if (query.ToUtc is { } to) source = source.Where(item => item.OccurredAtUtcTicks < to.UtcTicks);
        return source;
    }

    private static IOrderedQueryable<InteractionEventEntity> OrderForList(IQueryable<InteractionEventEntity> source) =>
        source.OrderByDescending(item => item.OccurredAtUtcTicks).ThenByDescending(item => item.Sequence)
            .ThenBy(item => EF.Functions.Collate(item.EventId, "BINARY"));
}
