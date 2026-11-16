using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Honeypot.Api.Common;
using Honeypot.Api.Data;
using Honeypot.Api.Data.Models;
using Honeypot.Api.Models;
using Honeypot.Api.Options;
using Honeypot.Api.Service;
using Honeypot.Api.Service.impl;
using Honeypot.Api.Workers;
using Honeypot.Protocol.Abstractions.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace Honeypot.Runtime.Tests;

public sealed class CredentialEvidencePersistenceTests
{
    private const string Password = "Isolated-Credential-Persistence#123";
    private const string Username = "isolated-account";
    private static readonly AuthenticatedUser Admin = new("isolated-admin", "isolated-admin", ["Administrator"]);

    [Fact]
    public async Task AnonymousEvidenceAuditOnlyRecordsValidRoutesWithinSharedQuota()
    {
        var fixture = await Fixture.CreateAsync();
        var evidence = await fixture.SaveAsync("anonymous-audit");
        using var access = fixture.OpenAccess();
        using var services = new ServiceCollection().AddSingleton<ICredentialEvidenceAccessService>(access).BuildServiceProvider();
        const string path = "/api/v1/credential-evidence";
        var detail = $"{path}/{evidence.CredentialArtifactId}";

        AuditRejection("GET", $"{path}/invalid-artifact");
        AuditRejection("POST", detail);
        AuditRejection("GET", $"{path}/export");
        AuditRejection("POST", $"{path}/export//");
        Assert.Empty(access.GetAuditTrail());

        AuditRejection("GET", detail);
        var first = Assert.Single(access.GetAuditTrail());
        Assert.Equal("UNAUTHORIZED", first.Outcome);
        Assert.Equal(evidence.CredentialArtifactId, first.CredentialArtifactId);
        for (var index = 0; index < 10; index++)
        {
            AuditRejection("POST", $"{path}/export");
            AuditRejection("GET", detail);
        }

        var anonymous = access.GetAuditTrail();
        Assert.Equal(4, anonymous.Count);
        Assert.All(anonymous, row => Assert.Null(row.UserId));
        Assert.Contains(anonymous, row => row.Operation == "Export");
        Assert.Equal(401, access.Read(evidence.CredentialArtifactId, null).StatusCode);
        var viewer = new AuthenticatedUser("viewer", "viewer", ["Viewer"]);
        Assert.Equal(403, access.Read(evidence.CredentialArtifactId, viewer).StatusCode);
        Assert.Equal(200, access.ReadForExport(evidence.CredentialArtifactId, Admin).StatusCode);
        Assert.Equal(6, access.GetAuditTrail().Count);

        void AuditRejection(string method, string requestPath)
        {
            var context = new DefaultHttpContext { RequestServices = services };
            context.Request.Method = method;
            context.Request.Path = requestPath;
            CredentialEvidenceEndpoints.AuditUnauthenticatedRead(context);
        }
    }

    [Fact]
    public async Task CiphertextGroupsAndAuditsSurviveReopeningWithSameDataDirectory()
    {
        var fixture = await Fixture.CreateAsync();
        var first = await fixture.RecordAsync("first", retentionDays: 1);
        var initialStore = fixture.OpenStore();
        Assert.Equal(200, fixture.OpenAccess(initialStore).Read(first.CredentialArtifactId!, Admin).StatusCode);
        fixture.Clock.Advance(TimeSpan.FromMinutes(1));

        var latest = await fixture.RecordAsync("latest", retentionDays: 2);
        await fixture.RecordAsync("other", password: Password + " ");
        var orphan = await fixture.SaveAsync("unconfirmed", username: "not-recorded-in-an-event");
        await fixture.RecordAsync("latest"); // 同一事件编号即使重复存证，也不能重复计数。

        var restarted = fixture.OpenStore();
        var grouped = restarted.GetPasswordBook();
        Assert.Equal(2, grouped.Count);
        var combined = Assert.Single(grouped, row => row.AuthenticationCount == 2);
        Assert.Equal(latest.CredentialArtifactId, combined.CredentialArtifactId);
        Assert.Equal(latest.OccurredAtUtc, combined.LastUsedAtUtc);
        Assert.DoesNotContain(grouped, row => row.CredentialArtifactId == orphan.CredentialArtifactId);

        using var page = JsonDocument.Parse(JsonSerializer.Serialize(restarted.GetPasswordBookPage(2, 1), new JsonSerializerOptions(JsonSerializerDefaults.Web)));
        Assert.Equal(2, page.RootElement.GetProperty("total").GetInt32());
        Assert.Equal(2, page.RootElement.GetProperty("page").GetInt32());
        Assert.Single(page.RootElement.GetProperty("items").EnumerateArray());
        Assert.DoesNotContain(Password, page.RootElement.GetRawText());
        Assert.DoesNotContain("fingerprint", page.RootElement.GetRawText(), StringComparison.OrdinalIgnoreCase);

        var reopenedAccess = fixture.OpenAccess(restarted);
        Assert.Equal(first.CredentialArtifactId, Assert.Single(reopenedAccess.GetAuditTrail()).CredentialArtifactId);
        Assert.Equal(403, reopenedAccess.Read(latest.CredentialArtifactId!, new("viewer", "viewer", ["Viewer"])).StatusCode);
        Assert.Contains(Password, reopenedAccess.Read(latest.CredentialArtifactId!, Admin).Evidence!.Content);
        Assert.Equal(3, fixture.OpenAccess().GetAuditTrail().Count);
        var databaseBytes = await File.ReadAllBytesAsync(fixture.DatabasePath);
        Assert.Equal(-1, databaseBytes.AsSpan().IndexOf(Encoding.UTF8.GetBytes(Password)));
        Assert.Equal(-1, databaseBytes.AsSpan().IndexOf(Encoding.UTF8.GetBytes("not-recorded-in-an-event")));

        fixture.Clock.Advance(TimeSpan.FromDays(1));
        Assert.Null(restarted.Get(first.CredentialArtifactId!));
        var surviving = Assert.Single(restarted.GetPasswordBook());
        Assert.Equal(latest.CredentialArtifactId, surviving.CredentialArtifactId);
        Assert.Equal(1, surviving.AuthenticationCount);
    }

    [Fact]
    public async Task SqlitePasswordBookSearchKeepsGroupedCountsAndFiltersBeforePaging()
    {
        var fixture = await Fixture.CreateAsync();
        const string account = "运维Alpha%_one";
        await fixture.RecordAsync("repeated-first", retentionDays: 2, username: account);
        await fixture.RecordAsync("expired-match", username: "运维Alpha%_expired");
        fixture.Clock.Advance(TimeSpan.FromMinutes(1));
        var second = await fixture.RecordAsync("second-match", retentionDays: 2, username: "运维Alpha%_two");
        fixture.Clock.Advance(TimeSpan.FromMinutes(1));
        var latest = await fixture.RecordAsync("repeated-latest", retentionDays: 2, username: account);
        fixture.Clock.Advance(TimeSpan.FromMinutes(1));
        var unmatched = await fixture.RecordAsync("wildcard-lookalike", retentionDays: 2, username: "运维AlphaXY", adapter: "redis");
        fixture.Clock.Advance(TimeSpan.FromDays(1));

        // 即使证据密钥不可用，摘要仍可依靠已确认索引分组与搜索。
        var reopened = fixture.OpenStore(fixture.Keys(Path.Combine(fixture.Directory, "unavailable-search-keys")));
        const string keyword = "  运维aLPHa%_  ";
        var firstPage = Assert.IsType<QueryPageResult<PasswordBookRow>>(reopened.GetPasswordBookPage(1, 1, keyword));
        Assert.Equal(2, firstPage.Total);
        var firstRow = Assert.Single(firstPage.Items);
        Assert.Equal(latest.CredentialArtifactId, firstRow.CredentialArtifactId);
        Assert.Equal(2, firstRow.AuthenticationCount);
        var secondPage = Assert.IsType<QueryPageResult<PasswordBookRow>>(reopened.GetPasswordBookPage(2, 1, keyword));
        Assert.Equal(2, secondPage.Total);
        Assert.Equal(second.CredentialArtifactId, Assert.Single(secondPage.Items).CredentialArtifactId);
        var pastEnd = Assert.IsType<QueryPageResult<PasswordBookRow>>(reopened.GetPasswordBookPage(int.MaxValue, 1, keyword));
        Assert.Equal(2, pastEnd.Total);
        Assert.Empty(pastEnd.Items);
        var service = Assert.IsType<QueryPageResult<PasswordBookRow>>(reopened.GetPasswordBookPage(1, 1, " eDI "));
        Assert.Equal(unmatched.CredentialArtifactId, Assert.Single(service.Items).CredentialArtifactId);
        var byPassword = Assert.IsType<QueryPageResult<PasswordBookRow>>(reopened.GetPasswordBookPage(1, 2, Password));
        Assert.Equal(0, byPassword.Total);
        Assert.Empty(byPassword.Items);
    }

    [Fact]
    public async Task SummaryPagesKeepStableOrderAndExcludeExpiredRowsFromTotal()
    {
        var fixture = await Fixture.CreateAsync();
        await fixture.SaveAsync("expires-at-cutoff");
        var older = await fixture.SaveAsync("older-active", retentionDays: 2);
        fixture.Clock.Advance(TimeSpan.FromMinutes(1));
        var newerA = await fixture.SaveAsync("newer-first", retentionDays: 2);
        var newerB = await fixture.SaveAsync("newer-second", retentionDays: 2);
        fixture.Clock.Advance(TimeSpan.FromDays(1) - TimeSpan.FromMinutes(1));

        var store = fixture.OpenStore();
        var first = store.GetPage(1, 2);
        Assert.Equal(3, first.Total);
        Assert.Equal(1, first.Page);
        Assert.Equal(2, first.PageSize);
        Assert.Equal(new[] { newerA.CredentialArtifactId, newerB.CredentialArtifactId }.Order(StringComparer.Ordinal),
            first.Items.Select(row => row.CredentialArtifactId));
        Assert.All(first.Items, row => Assert.Equal(newerA.CapturedAtUtc, row.CapturedAtUtc));

        var second = store.GetPage(2, 2);
        Assert.Equal(3, second.Total);
        Assert.Equal(older.CredentialArtifactId, Assert.Single(second.Items).CredentialArtifactId);
        var beyondLast = store.GetPage(int.MaxValue, 200);
        Assert.Equal((3, int.MaxValue, 100), (beyondLast.Total, beyondLast.Page, beyondLast.PageSize));
        Assert.Empty(beyondLast.Items);
    }

    [Fact]
    public async Task UncommittedEventDoesNotConfirmEvidenceAndRetentionRemovesExpiredRows()
    {
        var fixture = await Fixture.CreateAsync();
        var store = fixture.OpenStore();
        var evidence = await fixture.SaveAsync("rollback");
        await fixture.ConfirmAsync(store, Fixture.Event(evidence), commit: false);
        Assert.Empty(store.GetPasswordBook());
        Assert.NotNull(store.Get(evidence.CredentialArtifactId));
        Assert.Equal(200, fixture.OpenAccess().Read(evidence.CredentialArtifactId, Admin).StatusCode);

        // 凭据和审计过期后从查询即时移除，不等待后台清理。
        fixture.Clock.Advance(TimeSpan.FromDays(1));
        Assert.Empty(store.GetAll());
        Assert.Empty(fixture.OpenAccess().GetAuditTrail());
        using var worker = new CredentialEvidenceRetentionWorker(fixture.Factory, fixture.Clock, fixture.AuditOptions,
            NullLogger<CredentialEvidenceRetentionWorker>.Instance);
        await worker.RunOnceAsync(CancellationToken.None);
        await using var db = fixture.Factory.CreateDbContext();
        Assert.False(await db.Set<CredentialEvidenceEntity>().AnyAsync());
        Assert.False(await db.Set<CredentialEvidenceAccessAuditEntity>().AnyAsync());
    }

    [Fact]
    public async Task EvidenceIntakeContinuesPastTenThousandActiveEntries()
    {
        var fixture = await Fixture.CreateAsync();
        var first = await fixture.SaveAsync("before-count-threshold");
        await using (var db = fixture.Factory.CreateDbContext())
        {
            // 批量写入只用于模拟已达旧阈值的测试库，首条和阈值后的证据仍由真实存储路径加密。
            await db.Database.ExecuteSqlInterpolatedAsync($"""
                WITH RECURSIVE samples(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM samples WHERE n < 9999)
                INSERT INTO credential_evidence (
                    ArtifactId, ConnectionId, EventId, SourceIp, AdapterKey, MaterialType,
                    CapturedAtUtcTicks, RetentionUntilUtcTicks, KeyId, ContentBytes, Nonce, Tag, Ciphertext)
                SELECT 'cred-' || printf('%032x', samples.n), template.ConnectionId, 'sample-' || samples.n,
                    template.SourceIp, template.AdapterKey, template.MaterialType,
                    template.CapturedAtUtcTicks, template.RetentionUntilUtcTicks, template.KeyId,
                    template.ContentBytes, zeroblob(length(template.Nonce)), zeroblob(length(template.Tag)),
                    zeroblob(template.ContentBytes)
                FROM samples CROSS JOIN credential_evidence AS template
                WHERE template.ArtifactId = {first.CredentialArtifactId}
                """);
        }

        var store = fixture.OpenStore();
        Assert.Equal(10_000, store.GetPage(1, 1).Total);
        fixture.Clock.Advance(TimeSpan.FromMinutes(1));
        var added = await fixture.SaveAsync("after-count-threshold");
        var reopened = fixture.OpenStore();
        var page = reopened.GetPage(1, 1);
        Assert.Equal(10_001, page.Total);
        Assert.Equal(added, Assert.Single(page.Items));
        Assert.Contains(Password, reopened.Get(first.CredentialArtifactId)!.Content);
        Assert.Contains(Password, reopened.Get(added.CredentialArtifactId)!.Content);
    }

    [Fact]
    public async Task EvidenceIntakeStillEnforcesTheTotalByteLimit()
    {
        var fixture = await Fixture.CreateAsync();
        var capped = fixture.OpenStore(capacity: new() { MaxStoredMiB = 1 });
        var content = JsonSerializer.Serialize(new { material = new string('x', 600 * 1024) });
        var first = await Save(capped, "byte-limit-first");
        var rejected = await Assert.ThrowsAsync<InvalidOperationException>(() => Save(capped, "byte-limit-second"));
        Assert.Equal("CREDENTIAL_STORE_CAPACITY_EXCEEDED", rejected.Message);
        Assert.Equal(first, Assert.Single(capped.GetAll()));

        var reopened = fixture.OpenStore(capacity: new() { MaxStoredMiB = 2 });
        var second = await Save(reopened, "byte-limit-second");
        Assert.NotNull(reopened.Get(first.CredentialArtifactId));
        Assert.Equal(content, reopened.Get(second.CredentialArtifactId)!.Content);
        Assert.Equal(2, reopened.GetAll().Count);

        Task<CredentialEvidenceSummary> Save(SqliteCredentialEvidenceStore store, string eventId) =>
            store.SaveAsync("conn", eventId, "192.0.2.10", "ssh", "Response", content, 1);
    }

    [Fact]
    public async Task UnavailableKeysAreNotReplacedAndEvidenceRequiresAuditBeforeDisclosure()
    {
        var fixture = await Fixture.CreateAsync();
        var evidence = await fixture.SaveAsync("original");
        var other = await Fixture.CreateAsync();
        var otherDirectory = Path.Combine(other.Directory, "credential-evidence-keys");
        var wrongKeys = fixture.Keys(otherDirectory);
        var wrongStore = fixture.OpenStore(wrongKeys);
        await Assert.ThrowsAsync<CryptographicException>(() => wrongStore.SaveAsync("conn", "second", "192.0.2.10",
            "ssh", "Plaintext", "{}", 1));
        Assert.False(System.IO.Directory.Exists(otherDirectory));

        // 另一套独立的合成密钥格式合法，与数据库记录中的密钥标识不符。
        await other.SaveAsync("independent-test-key");
        var wrongResult = fixture.OpenAccess(wrongStore).Read(evidence.CredentialArtifactId, Admin);
        Assert.Equal("EVIDENCE_READ_FAILED", wrongResult.Code);
        Assert.Null(wrongResult.Evidence);
        await Assert.ThrowsAsync<CryptographicException>(() => wrongStore.SaveAsync("conn", "third", "192.0.2.10",
            "ssh", "Plaintext", "{}", 1));
        Assert.Equal("EVIDENCE_READ_FAILED", Assert.Single(fixture.OpenAccess().GetAuditTrail()).Outcome);
        Assert.NotNull(fixture.OpenStore().Get(evidence.CredentialArtifactId));

        var unavailableAudit = new CredentialEvidenceAccessService(fixture.OpenStore(), factory: new UnavailableFactory());
        var denied = unavailableAudit.Read(evidence.CredentialArtifactId, Admin);
        Assert.Equal("EVIDENCE_AUDIT_FAILED", denied.Code);
        Assert.Null(denied.Evidence);
    }

    private sealed class Fixture(string directory, string databasePath, Factory factory)
    {
        public string Directory { get; } = directory;
        public string DatabasePath { get; } = databasePath;
        public Factory Factory { get; } = factory;
        public TestClock Clock { get; } = new();
        public IOptions<CredentialEvidenceOptions> AuditOptions { get; } = Microsoft.Extensions.Options.Options.Create(
            new CredentialEvidenceOptions { AuditRetentionDays = 1 });

        public static async Task<Fixture> CreateAsync()
        {
            var directory = System.IO.Directory.CreateTempSubdirectory("honeypot-evidence-persistence-").FullName;
            var path = Path.Combine(directory, "evidence.db");
            var factory = new Factory(new DbContextOptionsBuilder<HoneypotDbContext>().UseSqlite($"Data Source={path};Pooling=False").Options);
            await using var db = factory.CreateDbContext();
            await db.Database.EnsureCreatedAsync();
            return new(directory, path, factory);
        }

        public SqliteCredentialEvidenceStore OpenStore(CredentialEvidenceKeys? keys = null, CredentialEvidenceOptions? capacity = null) =>
            new(Factory, keys ?? Keys(), Clock, new ReportEventDiskBudget(Clock), new ReportIngestionHealth(),
                Microsoft.Extensions.Options.Options.Create(new EventStorageOptions()),
                Microsoft.Extensions.Options.Options.Create(capacity ?? new CredentialEvidenceOptions()));

        public CredentialEvidenceKeys Keys(string? keyDirectory = null) => new(
            new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["Honeypot:DataDirectory"] = Directory }).Build(),
            new TestEnvironment(), Microsoft.Extensions.Options.Options.Create(new CredentialEvidenceOptions { KeyDirectory = keyDirectory }));

        public CredentialEvidenceAccessService OpenAccess(SqliteCredentialEvidenceStore? store = null) =>
            new(store ?? OpenStore(), factory: Factory, clock: Clock, options: AuditOptions);

        public Task<CredentialEvidenceSummary> SaveAsync(string eventId, string password = Password, string username = Username,
            int retentionDays = 1, string adapter = "ssh") => OpenStore().SaveAsync("conn", eventId, "192.0.2.10", adapter, "Plaintext",
            JsonSerializer.Serialize(new { username, password }), retentionDays);

        public async Task<InteractionEvent> RecordAsync(string eventId, string password = Password, int retentionDays = 1,
            string username = Username, string adapter = "ssh")
        {
            var evidence = await SaveAsync(eventId, password, username, retentionDays, adapter);
            var item = Event(evidence) with { Username = username };
            await ConfirmAsync(OpenStore(), item);
            return item;
        }

        public async Task ConfirmAsync(SqliteCredentialEvidenceStore store, InteractionEvent item, bool commit = true)
        {
            await using var db = Factory.CreateDbContext();
            await using var transaction = await db.Database.BeginTransactionAsync();
            await store.ConfirmPasswordBookAttemptAsync(db, item, CancellationToken.None, Clock.GetUtcNow());
            await db.SaveChangesAsync();
            if (commit) await transaction.CommitAsync();
        }

        public static InteractionEvent Event(CredentialEvidenceSummary evidence) => new()
        {
            EventId = evidence.EventId, ConnectionId = evidence.ConnectionId, OccurredAtUtc = evidence.CapturedAtUtc,
            EventType = "AuthenticationAttempted", Outcome = "failure", SourceIp = evidence.SourceIp,
            DestinationIp = "192.0.2.20", ListenerId = "listener", ServiceInstanceId = "instance",
            AdapterKey = evidence.AdapterKey, ProfileId = "profile", Username = Username, AuthenticationMethod = "password",
            MaterialType = evidence.MaterialType, CredentialArtifactId = evidence.CredentialArtifactId,
        };
    }

    private sealed class Factory(DbContextOptions<HoneypotDbContext> options) : IDbContextFactory<HoneypotDbContext>
    {
        public HoneypotDbContext CreateDbContext() => new(options);
    }

    private sealed class UnavailableFactory : IDbContextFactory<HoneypotDbContext>
    {
        public HoneypotDbContext CreateDbContext() => throw new IOException("Test audit storage unavailable");
    }

    private sealed class TestEnvironment : IHostEnvironment
    {
        public string ApplicationName { get; set; } = "Honeypot.Test";
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
        public string ContentRootPath { get; set; } = "";
        public string EnvironmentName { get; set; } = "Testing";
    }

    private sealed class TestClock : TimeProvider
    {
        private DateTimeOffset _current = new(2026, 11, 15, 0, 0, 0, TimeSpan.Zero);
        public override DateTimeOffset GetUtcNow() => _current;
        public void Advance(TimeSpan duration) => _current += duration;
    }
}
