using Honeypot.Api.Models;
using Honeypot.Api.Options;
using Honeypot.Api.Workers;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Honeypot.Runtime.Tests;

public sealed partial class ReportTests
{
    [Fact]
    public async Task RecentActivityPagesUseExactTotalBeforeAndAfterDetailExpiryAndCleanup()
    {
        var clock = new MutableTime(Start);
        var settings = new EventStorageOptions { DetailRetentionDays = 1, HandshakeRetentionHours = 1 };
        await using var fixture = await Fixture.CreateAsync(time: clock, storage: settings);
        var store = fixture.Store();

        async Task Append(string id, string connectionId, string type, long sequence = 7)
        {
            var item = Event(id, type, clock.GetUtcNow()) with
            {
                ConnectionId = connectionId, Sequence = sequence,
                Outcome = type == "HandshakeReceived" ? "observed" : "recorded",
            };
            Assert.True((await store.AppendAsync(item)).Recorded);
        }

        await Append("expired-auth", "ongoing-auth", "AuthenticationAttempted");
        Assert.Equal("expired-auth", Assert.Single(store.ReadActivities(new()).Items).EventId);
        await Append("expired-representative", "ongoing-connection", "ConnectionAccepted");
        await Append("expires-both-ways", "old-handshake", "HandshakeReceived");
        clock.Advance(TimeSpan.FromHours(23));
        await Append("later-close", "ongoing-connection", "SessionClosed", 8);
        await Append("expires-short-only", "recent-handshake", "HandshakeReceived");

        // 同时间同序号跨多个连接与认证时，BINARY 顺序应跨页稳定。
        await Append("Z-visible", "ongoing-auth", "AuthorizationDenied");
        await Append("m-visible", "another-auth", "AuthenticationAttempted");
        await Append("B-visible", "new-connection", "ConnectionAccepted");
        await Append("a-visible", "ongoing-auth", "AuthenticationAttempted");
        // 大小写变体在全库仍是同一事件，跨连接重放不能把代表转移给另一条连接。
        var replay = Event("b-VISIBLE", "AuthenticationAttempted", clock.GetUtcNow()) with { ConnectionId = "replay-connection" };
        Assert.True((await store.AppendAsync(replay)).IsDuplicate);
        Assert.Null(store.ReadConnectionSummary(replay.ConnectionId));
        clock.Advance(TimeSpan.FromHours(1));

        using var db = fixture.Factory.CreateDbContext();
        int PhysicalRows() => db.Database.SqlQueryRaw<int>("SELECT COUNT(*) AS Value FROM interaction_events").Single();
        void VerifyPages()
        {
            var first = store.ReadActivities(new InteractionEventQuery(Page: 1, PageSize: 2));
            var second = store.ReadActivities(new InteractionEventQuery(Page: 2, PageSize: 2));
            var beyond = store.ReadActivities(new InteractionEventQuery(Page: 3, PageSize: 2));
            Assert.Equal(4, first.Total);
            Assert.Equal(first.Total, second.Total);
            Assert.Equal(first.Total, beyond.Total);
            Assert.Equal(new[] { "B-visible", "Z-visible" }, first.Items.Select(row => row.EventId));
            Assert.Equal("new-connection", first.Items[0].ConnectionId);
            Assert.Equal(new[] { "a-visible", "m-visible" }, second.Items.Select(row => row.EventId));
            Assert.Empty(beyond.Items);

            // 同一隔离来源的筛选查询独立计算认证及代表项，两种计数路径在清理前后应逐项一致。
            var filtered = store.ReadActivities(new InteractionEventQuery(SourceIp: "192.0.2.10", PageSize: 10));
            Assert.Equal(first.Total, filtered.Total);
            Assert.Equal(first.Items.Concat(second.Items).OrderBy(item => item.EventId, StringComparer.Ordinal),
                filtered.Items.OrderBy(item => item.EventId, StringComparer.Ordinal));
        }

        Assert.Equal(9, PhysicalRows());
        VerifyPages();
        using var retention = new ReportEventRetentionWorker(fixture.Factory, Microsoft.Extensions.Options.Options.Create(settings),
            fixture.Health, clock, new(), NullLogger<ReportEventRetentionWorker>.Instance);
        await retention.RunOnceAsync(CancellationToken.None);
        Assert.Equal(5, PhysicalRows());
        // 关闭延长了摘要寿命，旧接纳、旧认证和短留代表已经物理清理。
        Assert.Equal(1, store.ReadConnectionSummary("ongoing-connection")!.AvailableCount);
        Assert.Equal(2, store.ReadConnectionSummary("ongoing-auth")!.AvailableCount);
        Assert.Equal(0, store.ReadConnectionSummary("recent-handshake")!.AvailableCount);
        VerifyPages();
    }
}
