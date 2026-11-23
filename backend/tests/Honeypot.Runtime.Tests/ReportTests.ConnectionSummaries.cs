using System.Text.Json;
using Honeypot.Api.Common;
using Honeypot.Api.Data;
using Honeypot.Api.Models;
using Honeypot.Api.Options;
using Honeypot.Api.Service;
using Honeypot.Api.Service.impl;
using Honeypot.Api.Workers;
using Honeypot.Engine.Service;
using Honeypot.Protocol.Abstractions.Models;
using Honeypot.Protocol.Abstractions.Service;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace Honeypot.Runtime.Tests;

public sealed partial class ReportTests
{
    [Fact]
    public async Task HandshakeExpiresWithoutLosingConnectionCountsOrAuthenticationAttempts()
    {
        var clock = new MutableTime(Start);
        await using var fixture = await Fixture.CreateAsync(time: clock);
        var store = fixture.Store();
        var connection = Event("start", "ConnectionAccepted", Start) with { Sequence = 1, SourcePort = 50123 };
        var handshake = connection with { EventId = "handshake", EventType = "HandshakeReceived", Sequence = 2, Stage = "negotiation", Outcome = "observed" };
        var problem = connection with { EventId = "truncated", EventType = "HandshakeReceived", Sequence = 3, CaptureTruncated = true };
        var first = connection with { EventId = "attempt1", EventType = "AuthenticationAttempted", Sequence = 4, AuthenticationAttempt = 1, Outcome = "failure", Stage = "auth" };
        var second = first with { EventId = "attempt2", Sequence = 5, AuthenticationAttempt = 2 };
        var closed = connection with { EventId = "closed", EventType = "SessionClosed", Sequence = 6, CloseReason = SessionCloseReason.AdapterCompleted, Stage = "closed" };
        foreach (var item in new[] { connection, handshake, problem, first, second, closed })
            Assert.True((await store.AppendAsync(item)).Recorded);
        var other = connection with { ConnectionId = "incomplete", EventId = "incomplete-accept" };
        await store.AppendAsync(other);
        clock.Advance(TimeSpan.FromHours(48));
        var restarted = await fixture.RecreateStoreAsync();
        var trace = restarted.ReadConnectionSummary(connection.ConnectionId)!;
        Assert.Equal((6, 5, "auth", "AdapterCompleted"), (trace.ObservedCount, trace.AvailableCount, trace.LastStage, trace.CloseReason));
        Assert.Equal("accepted", trace.AdmissionOutcome);
        Assert.Null(restarted.ReadConnectionSummary("incomplete")!.ClosedAtUtc);
        var remaining = restarted.GetByConnectionId(connection.ConnectionId).Select(row => row.EventId).ToArray();
        Assert.Equal(new[] { "start", "truncated", "attempt1", "attempt2", "closed" }, remaining);
        var activities = restarted.ReadActivities(new()).Items.Where(item => item.ConnectionId == connection.ConnectionId).ToArray();
        Assert.Equal(2, activities.Length);
        Assert.All(activities, row => { Assert.Equal(6, row.EventCount); Assert.True(row.ConnectionCloseObserved); });
        Assert.True((await restarted.AppendAsync(handshake)).IsDuplicate);
        var retention = new ReportEventRetentionWorker(fixture.Factory, Microsoft.Extensions.Options.Options.Create(new EventStorageOptions()),
            fixture.Health, clock, new ReportEventDiskBudget(), NullLogger<ReportEventRetentionWorker>.Instance);
        await retention.RunOnceAsync(default);
        using var db = fixture.Factory.CreateDbContext();
        var physical = await db.Database.SqlQuery<int>($"SELECT COUNT(*) AS Value FROM interaction_events WHERE EventId={handshake.EventId}").SingleAsync();
        Assert.Equal(0, physical);
        Assert.Equal(6, restarted.ReadConnectionSummary(connection.ConnectionId)!.ObservedCount);
        Assert.True((await restarted.AppendAsync(handshake)).IsDuplicate);
    }

    [Fact]
    public async Task LegacyMigrationBackfillsOnlyObservedConnectionsAndKeepsOriginalDetailLifetime()
    {
        var clock = new MutableTime(Start);
        await using var fixture = await Fixture.CreateAsync(createSchema:false, time:clock);
        await using var db = fixture.Factory.CreateDbContext();
        var migrator = db.Database.GetService<IMigrator>();
        await migrator.MigrateAsync("20261115085711_BusinessDataPersistence");
        var legacy = Event("old-banner", "BannerSent", Start) with { Sequence = 2, Stage = "banner", Outcome = "sent" };
        var json = JsonSerializer.Serialize(legacy);
        await db.Database.ExecuteSqlInterpolatedAsync($"""
            INSERT INTO interaction_events
            (EventId,ConnectionId,Sequence,OccurredAtUtcTicks,ReceivedAtUnixMs,SourceIp,AdapterKey,EventType,DestinationPort,ActivityPriority,EventJson)
            VALUES({legacy.EventId},{legacy.ConnectionId},{legacy.Sequence},{Start.UtcTicks},{Start.ToUnixTimeMilliseconds()},
                {legacy.SourceIp},{legacy.AdapterKey},{legacy.EventType},{legacy.DestinationPort},0,{json})
            """);
        await db.Database.ExecuteSqlInterpolatedAsync($"""
            INSERT INTO report_events
            (EventId,OccurredAtUnixMs,EventType,SourceIp,AdapterKey,DestinationPort,Username,AuthenticationMethod,IsAuthenticationFailure,RiskSignal,EvidenceKind,CaptureTruncated)
            VALUES('only-report',{Start.ToUnixTimeMilliseconds()},'connectionaccepted','192.0.2.19','ssh',22,'','',0,'none','none',0)
            """);
        await migrator.MigrateAsync();
        clock.Advance(TimeSpan.FromDays(3));
        var store = fixture.Store();
        var trace = store.ReadConnectionSummary(legacy.ConnectionId)!;
        Assert.Null(trace.AdmittedAtUtc);
        Assert.Null(trace.ClosedAtUtc);
        Assert.Equal((1, 1, "banner"), (trace.ObservedCount,trace.AvailableCount,trace.LastStage));
        Assert.Single(store.GetByConnectionId(legacy.ConnectionId));
        Assert.Equal(1, await db.Database.SqlQueryRaw<int>("SELECT COUNT(*) AS Value FROM connection_summaries").SingleAsync());
    }

    [Fact]
    public async Task RollbackWritersAreReconciledOnceOnReupgrade()
    {
        var clock = new MutableTime(Start);
        await using var fixture = await Fixture.CreateAsync(createSchema: false, time: clock);
        await using var db = fixture.Factory.CreateDbContext();
        await db.Database.MigrateAsync();
        var store = fixture.Store();
        var accepted = Event("new-admit","ConnectionAccepted",Start) with { Sequence = 1 };
        Assert.True((await store.AppendAsync(accepted)).Recorded);
        var old = accepted with { EventId = "legacy-after-downgrade", EventType = "AuthenticationAttempted", Sequence = 2, Outcome = "failure" };
        var json = JsonSerializer.Serialize(old);
        // 回退二进制不识别新增列，省略的 Outcome 由迁移默认值填空；已有摘要仍应累计一次。
        await db.Database.ExecuteSqlInterpolatedAsync($"""
            INSERT INTO report_events
            (EventId,OccurredAtUnixMs,EventType,SourceIp,AdapterKey,DestinationPort,Username,AuthenticationMethod,IsAuthenticationFailure,RiskSignal,EvidenceKind,CaptureTruncated)
            VALUES({old.EventId},{Start.ToUnixTimeMilliseconds()},'authenticationattempted',{old.SourceIp},'ssh',22,'','',1,'none','none',0);
            """);
        await db.Database.ExecuteSqlInterpolatedAsync($"""
            INSERT INTO interaction_events
            (EventId,ConnectionId,Sequence,OccurredAtUtcTicks,ReceivedAtUnixMs,SourceIp,AdapterKey,EventType,DestinationPort,ActivityPriority,EventJson)
            VALUES({old.EventId},{old.ConnectionId},2,{Start.UtcTicks},{Start.ToUnixTimeMilliseconds()},
                {old.SourceIp},'ssh','AuthenticationAttempted',22,4,{json});
            """);
        var initializer = new HoneypotDbInitializer(fixture.Factory);
        await initializer.StartAsync(default);
        await initializer.StartAsync(default);
        var trace = store.ReadConnectionSummary(old.ConnectionId)!;
        Assert.Equal(2, trace.ObservedCount);
        Assert.Equal(2, Assert.Single(store.ReadActivities(new()).Items).EventCount);
    }

    [Fact]
    public async Task PersistentOverviewCountsAndAllPopupScopesMatchEachOtherBeyondSnapshotLimit()
    {
        var clock = new MutableTime(Start);
        await using var fixture = await Fixture.CreateAsync(time:clock, storage:new EventStorageOptions { MemoryEventCapacity = 1 });
        var store = fixture.Store();
        var a = Event("a","ConnectionAccepted",Start.AddHours(-1)) with { Sequence=1, ConnectionId="c-a", SourcePort=51234 };
        var b = a with { EventId="b", ConnectionId="c-b", SourceIp="192.0.2.12" };
        var attempt = a with { EventId="login",EventType="AuthenticationAttempted",Sequence=2,OccurredAtUtc=Start.AddMinutes(1),
            Outcome="failure",Username="synthetic",MaterialType="Plaintext",CredentialArtifactId="synthetic-id" };
        var escaped = b with { EventId="error",EventType="ProtocolViolation",Sequence=2,PayloadSummary="Malformed frame" };
        var rejected = b with { EventId="denied",ConnectionId="c-denied",EventType="ConnectionRejected",Outcome="rejected" };
        var later = a with { EventId="later",ConnectionId="c-later",OccurredAtUtc=Start.AddMinutes(9) };
        foreach (var item in new[] {a,b,attempt,escaped,rejected,later}) Assert.True((await store.AppendAsync(item)).Recorded);
        // 只有旧报告事实，位于今日窗口。仍可进入报告趋势，无法用来补造可下钻的接纳连接。
        await using (var db = fixture.Factory.CreateDbContext())
        {
            db.Set<Honeypot.Api.Data.Models.ReportEventEntity>().Add(new()
            {
                EventId="legacy-fact", OccurredAtUnixMs=Start.ToUnixTimeMilliseconds(),
                EventType="connectionaccepted", SourceIp="192.0.2.99", AdapterKey="ssh", Outcome="",
            });
            await db.SaveChangesAsync();
        }
        clock.Advance(TimeSpan.FromMinutes(10));
        var listener = new OverviewActivityTests.SnapshotListener(new("live",clock.GetUtcNow(),a.SourceIp,a.SourcePort,a.AdapterKey,a.DestinationPort));
        var metrics = OverviewMetricsReader.Read(store,fixture.Threats(),listener,new InMemoryServiceInstanceStore(),clock.GetUtcNow(),false);
        Assert.Equal((3,1,1), (metrics.AcceptedConnections,metrics.TodayAuthenticationFailures,metrics.ProtocolViolations));
        Assert.Equal(1,metrics.ReportOnlyEvents);
        Assert.Equal(4,metrics.ActivityByHour.Sum(row=>row.AcceptedConnections));
        Assert.Equal(2,metrics.TraceableThreatIpCount);
        var appBuilder = WebApplication.CreateSlimBuilder();
        appBuilder.WebHost.UseUrls("http://127.0.0.1:0");
        appBuilder.Logging.ClearProviders();
        appBuilder.Services.AddSingleton<IInteractionEventStore>(store);
        appBuilder.Services.AddSingleton<IListenerHost>(listener);
        appBuilder.Services.AddSingleton<IThreatProfileStore>(fixture.Threats());
        appBuilder.Services.AddSingleton<TimeProvider>(clock);
        appBuilder.Services.AddSingleton<OverviewActiveConnections>();
        appBuilder.Services.AddSingleton<IServiceInstanceStore>(new InMemoryServiceInstanceStore());
        appBuilder.Services.AddSingleton(fixture.Health);
        appBuilder.Services.AddSingleton(new SqliteReportService(fixture.Factory, clock));
        await using var app = appBuilder.Build();
        app.MapOverviewMetricsEndpoint();
        app.MapOverviewConnectionsEndpoints();
        app.MapInteractionEventEndpoints();
        await app.StartAsync();
        try
        {
            using var client = new HttpClient { BaseAddress=new Uri(Assert.Single(app.Urls)) };
            async Task<JsonElement> Read(string query)
            {
                var json = await client.GetStringAsync("/api/v1/metrics/overview/connections?"+query);
                using var doc = JsonDocument.Parse(json);
                return doc.RootElement.GetProperty("data").Clone();
            }
            Assert.Equal(3,(await Read("scope=accepted")).GetProperty("total").GetInt32());
            var cutoff = Uri.EscapeDataString(Start.AddMinutes(3).ToString("O"));
            Assert.Equal(2,(await Read("scope=accepted&asOfUtc="+cutoff)).GetProperty("total").GetInt32());
            Assert.Equal(2,(await Read("scope=threatConnections")).GetProperty("total").GetInt32());
            Assert.Equal("synthetic",(await Read("scope=authenticationFailures")).GetProperty("items")[0].GetProperty("username").GetString());
            Assert.Equal(3,(await Read("scope=adapterActivity&adapterKey=ssh&metric=acceptedConnections")).GetProperty("total").GetInt32());
            Assert.Equal(2,(await Read("scope=adapterActivity&adapterKey=ssh&metric=sourceIpCount")).GetProperty("total").GetInt32());
            Assert.Equal("Malformed frame",(await Read("scope=adapterActivity&adapterKey=ssh&metric=protocolViolations")).GetProperty("items")[0].GetProperty("protocolViolationSummary").GetString());
            var live = listener.Active.Single();
            listener.Active = [live, live with { ConnectionId = "second", AcceptedAtUtc = live.AcceptedAtUtc.AddTicks(-1) }];
            async Task<JsonElement> Card()
            {
                using var response = JsonDocument.Parse(await client.GetStringAsync("/api/v1/metrics/overview"));
                return response.RootElement.GetProperty("data").Clone();
            }
            var card = await Card();
            var stamp = Uri.EscapeDataString(card.GetProperty("generatedAtUtc").GetString()!);
            Assert.Equal(2, card.GetProperty("activeConnections").GetInt32());
            listener.Active = [live with { ConnectionId = "new" }];
            // 同一秒重复刷新的卡片、旧卡的跨页查询、无时间参数的现场查询采用各自的列表。
            Assert.Equal(2, (await Card()).GetProperty("activeConnections").GetInt32());
            var page2 = await Read($"scope=active&asOfUtc={stamp}&page=2&pageSize=1");
            Assert.Equal(2, page2.GetProperty("total").GetInt32());
            Assert.Equal("second",page2.GetProperty("items")[0].GetProperty("connectionId").GetString());
            Assert.Equal("new",(await Read("scope=active")).GetProperty("items")[0].GetProperty("connectionId").GetString());
            clock.Advance(TimeSpan.FromSeconds(1));
            Assert.Equal(1, (await Card()).GetProperty("activeConnections").GetInt32());
            Assert.Equal(2,(await Read($"scope=active&asOfUtc={stamp}")).GetProperty("total").GetInt32());
            clock.Advance(TimeSpan.FromMinutes(5));
            using var expired = await client.GetAsync($"/api/v1/metrics/overview/connections?scope=active&asOfUtc={stamp}");
            Assert.Equal(System.Net.HttpStatusCode.Gone, expired.StatusCode);
            Assert.Contains("OVERVIEW_SNAPSHOT_EXPIRED",await expired.Content.ReadAsStringAsync());
            var rejectedTrace = await client.GetStringAsync("/api/v1/connections/c-denied/summary");
            Assert.Contains("\"admissionOutcome\":\"rejected\"",rejectedTrace);
        }
        finally { await app.StopAsync(); }
    }
}
