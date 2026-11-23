using Honeypot.Api.Common;
using Honeypot.Api.Data;
using Honeypot.Api.Data.Models;
using Honeypot.Api.Models;
using Honeypot.Protocol.Abstractions.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.Data.Sqlite;

namespace Honeypot.Api.Service.impl;

public sealed partial class ReportInteractionEventStore
{
    public IReadOnlyCollection<InteractionEvent> GetAll()
    {
        using var db = OpenReadContext();
        var now = _time.GetUtcNow();
        var recent = now.AddHours(-_options.MemoryRetentionHours).ToUnixTimeMilliseconds();
        // 保留兼容调用所需的有界快照。首页、地图和历史列表分别使用专门的查询。
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
        var now = _time.GetUtcNow();
        var active = Active(db, now);
        var (page, size, offset) = QueryPage.Bounds(query.Page, query.PageSize);
        db.Database.OpenConnection();
        using var read = ((SqliteConnection)db.Database.GetDbConnection()).BeginTransaction(deferred: true);
        using var contextTransaction = db.Database.UseTransaction(read);
        if (query.ConnectionIds is null && string.IsNullOrWhiteSpace(query.SourceIp) && string.IsNullOrWhiteSpace(query.AdapterKey) &&
            string.IsNullOrWhiteSpace(query.EventType) && query.DestinationPort is null && query.FromUtc is null && query.ToUtc is null)
        {
            return ReadRecentActivityPage(db, now.AddDays(-_options.DetailRetentionDays).ToUnixTimeMilliseconds(),
                now.ToUnixTimeMilliseconds(), page, size, offset);
        }
        var steps = FilterConnection(active, query);
        var summaries = db.Set<ConnectionSummaryEntity>().AsNoTracking();

        // 显式 connectionIds 过滤按原始 ID 大小写执行，保留历史导出和精确筛选口径。
        if (query.ConnectionIds is not null)
        {
            var reps = steps.Where(item => item.ActivityPriority == InteractionActivityProjection.Authentication ||
                item.EventId == steps.Where(step => step.ConnectionId == item.ConnectionId)
                    .OrderByDescending(step => step.ActivityPriority)
                    .ThenBy(step => step.ActivityPriority == InteractionActivityProjection.Accepted ? step.Sequence : 0L)
                    .ThenByDescending(step => step.Sequence)
                    .ThenBy(step => step.ActivityPriority == InteractionActivityProjection.Accepted ? step.OccurredAtUtcTicks : 0L)
                    .ThenByDescending(step => step.OccurredAtUtcTicks).ThenBy(step => step.EventId).Select(step => step.EventId).First());
            var filtered = FilterEvent(reps, query);
            var total = filtered.Count();
            var keys = offset < total ? OrderForList(filtered).Skip((int)offset).Take(size).Select(item =>
                new ActivityPageKey(item.EventId, steps.Count(x => x.ConnectionId == item.ConnectionId),
                    summaries.Any(x => x.ConnectionId == item.ConnectionId && x.ClosedAtUtcTicks != null),
                    item.OccurredAtUtcTicks, item.Sequence)).ToArray() : [];
            return new(ReadActivityRows(db, keys), total, page, size);
        }

        // 普通列表使用持久代表步骤或逐次认证，不再针对每条候选明细重算同一连接的优先级。
        var visible = steps.Where(item => item.ActivityPriority == InteractionActivityProjection.Authentication ||
            summaries.Any(row => row.ConnectionId == item.ConnectionId && row.AuthenticationActivityCount == 0 &&
                row.RepresentativeId == item.EventId));
        var results = FilterEvent(visible, query);

        // 两类活动互斥。认证走已有事件类型索引，其余连接按代表事件主键查找，仅扫描连接行。
        var qualifying = FilterEvent(steps, query);
        var count = qualifying.Count(item => item.EventType == "AuthenticationAttempted" || item.EventType == "AuthorizationDenied") +
            summaries.Where(summary => summary.AuthenticationActivityCount == 0)
                .Join(qualifying, summary => summary.RepresentativeId, item => item.EventId, (summary, item) => item.EventId).Count();
        if (offset >= count) return new([], count, page, size);
        var rows = from item in results join summary in summaries on item.ConnectionId equals summary.ConnectionId
                   select new { Item = item, Summary = summary };
        var selected = rows.OrderByDescending(row => row.Item.OccurredAtUtcTicks)
            .ThenByDescending(row => row.Item.Sequence).ThenBy(row => row.Item.EventId)
            .Skip((int)offset).Take(size).Select(row => new ActivityPageKey(row.Item.EventId, row.Summary.ObservedCount,
                row.Summary.ClosedAtUtcTicks != null, row.Item.OccurredAtUtcTicks, row.Item.Sequence)).ToArray();
        return new(ReadActivityRows(db, selected), count, page, size);
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
        var end = now.ToUnixTimeMilliseconds();
        return db.Set<InteractionEventEntity>().AsNoTracking().Where(item => item.ReceivedAtUnixMs > cutoff &&
            (item.ShortRetentionUntilUnixMs == null || item.ShortRetentionUntilUnixMs > end));
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
