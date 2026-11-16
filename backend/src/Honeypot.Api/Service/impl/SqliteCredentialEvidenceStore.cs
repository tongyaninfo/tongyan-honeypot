using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Honeypot.Api.Common;
using Honeypot.Api.Data;
using Honeypot.Api.Data.Models;
using Honeypot.Api.Models;
using Honeypot.Api.Options;
using Honeypot.Protocol.Abstractions.Models;
using Honeypot.Shared.Models;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Honeypot.Api.Service.impl;

/// <summary>凭据只保存密文。密码簿依据有效凭据中的已确认认证事件生成。</summary>
public sealed class SqliteCredentialEvidenceStore(IDbContextFactory<HoneypotDbContext> factory,
    CredentialEvidenceKeys keys, TimeProvider clock, ReportEventDiskBudget diskBudget,
    ReportIngestionHealth health, IOptions<EventStorageOptions> options, IOptions<CredentialEvidenceOptions> evidenceOptions,
    ISyslogPublisher? syslog = null)
    : ICredentialEvidenceStore
{
    private const int MiB = 1024 * 1024;
    private const int MaxEvidenceBytes = 4 * MiB;

    public async Task<CredentialEvidenceSummary> SaveAsync(string connectionId, string eventId, string sourceIp,
        string adapterKey, string materialType, string content, int retentionDays, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (retentionDays is < 1 or > 3650) throw new ArgumentOutOfRangeException(nameof(retentionDays));
        if (!ValidMetadata(connectionId, 128) || !ValidMetadata(eventId, 128) || !ValidMetadata(sourceIp, 64) ||
            !ValidMetadata(adapterKey, 64) || !ValidMetadata(materialType, 64))
            throw new ArgumentException("CREDENTIAL_EVIDENCE_INVALID_METADATA");

        try
        {
            var contentBytes = Encoding.UTF8.GetByteCount(content);
            if (contentBytes > MaxEvidenceBytes) throw new InvalidOperationException("CREDENTIAL_STORE_CAPACITY_EXCEEDED");

            await using var db = await factory.CreateDbContextAsync(cancellationToken);
            SetTimeout(db);
            await db.Database.OpenConnectionAsync(cancellationToken);
            if (!await diskBudget.CanWriteAsync(db, options.Value, health, cancellationToken))
                throw new InvalidOperationException("CREDENTIAL_EVIDENCE_DISK_BUDGET_EXCEEDED");

            await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
            var capturedAt = clock.GetUtcNow();
            var entries = db.Set<CredentialEvidenceEntity>();
            // 同一写事务检查有效证据的总字节数并落盘，避免并发采集同时越过上限。
            var storedBytes = await entries.Where(row => row.RetentionUntilUtcTicks > capturedAt.UtcTicks)
                .SumAsync(row => (long)row.ContentBytes, cancellationToken);
            if (storedBytes + contentBytes > (long)evidenceOptions.Value.MaxStoredMiB * MiB)
                throw new InvalidOperationException("CREDENTIAL_STORE_CAPACITY_EXCEEDED");

            using var key = keys.Read(mayInitialize: !await entries.AnyAsync(cancellationToken));
            if (await entries.AnyAsync(row => row.KeyId != key.Id, cancellationToken))
                throw new CryptographicException("CREDENTIAL_EVIDENCE_KEY_MISMATCH");

            var summary = new CredentialEvidenceSummary($"cred-{Guid.NewGuid():N}", connectionId, eventId, sourceIp,
                adapterKey, materialType, capturedAt.ToUniversalTime(), capturedAt.AddDays(retentionDays).ToUniversalTime(), false);
            entries.Add(Encrypt(summary, content, contentBytes, key));
            await db.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            health.SetDiskBudgetBlocked(false);
            SyslogInteractionProjection.PublishSafely(syslog, "honeypot-evidence", "EVIDENCE_CAPTURED", SyslogSeverity.Informational,
                new Dictionary<string, object?> { ["credentialArtifactId"] = summary.CredentialArtifactId, ["eventId"] = eventId,
                    ["connectionId"] = connectionId, ["adapterKey"] = adapterKey, ["materialType"] = materialType,
                    ["outcome"] = "captured" });
            return summary;
        }
        catch (Exception error) when (error is not OperationCanceledException)
        {
            if ((error is DbUpdateException ? error.InnerException : error) is SqliteException { SqliteErrorCode: 13 })
                health.SetDiskBudgetBlocked(true);
            // 日志只保留有界元数据。数据库和文件异常可能附带路径或用户数据。
            SyslogInteractionProjection.PublishSafely(syslog, "honeypot-evidence", "EVIDENCE_CAPTURE_FAILED", SyslogSeverity.Error,
                new Dictionary<string, object?> { ["eventId"] = eventId, ["connectionId"] = connectionId,
                    ["adapterKey"] = adapterKey, ["errorCode"] = "EVIDENCE_CAPTURE_FAILED" });
            throw;
        }
    }

    public CredentialEvidenceView? Get(string credentialArtifactId)
    {
        using var db = factory.CreateDbContext();
        SetTimeout(db);
        var now = clock.GetUtcNow().UtcTicks;
        var row = db.Set<CredentialEvidenceEntity>().AsNoTracking().SingleOrDefault(item =>
            item.ArtifactId == credentialArtifactId && item.RetentionUntilUtcTicks > now);
        if (row is null) return null;

        using var key = keys.Read(mayInitialize: false);
        var summary = ToSummary(row);
        var plaintext = new byte[row.Ciphertext.Length];
        try
        {
            Decrypt(row, summary, key, plaintext);
            return new(summary, Encoding.UTF8.GetString(plaintext));
        }
        finally { CryptographicOperations.ZeroMemory(plaintext); }
    }

    public IReadOnlyCollection<CredentialEvidenceSummary> GetAll()
    {
        using var db = factory.CreateDbContext();
        SetTimeout(db);
        return ProjectSummaries(OrderedSummaryRows(db, clock.GetUtcNow().UtcTicks)).ToArray();
    }

    public QueryPageResult<CredentialEvidenceSummary> GetPage(int? page, int? pageSize)
    {
        var (number, size, offset) = QueryPage.Bounds(page, pageSize);
        using var db = factory.CreateDbContext();
        SetTimeout(db);
        db.Database.OpenConnection();
        // 共享延迟读事务让总数和当前页看到同一快照，写入和过期清理不会引起分页漂移。
        using var transaction = ((SqliteConnection)db.Database.GetDbConnection()).BeginTransaction(deferred: true);
        using var contextTransaction = db.Database.UseTransaction(transaction);
        var rows = OrderedSummaryRows(db, clock.GetUtcNow().UtcTicks);
        var total = rows.Count();
        var items = offset < total ? ProjectSummaries(rows.Skip((int)offset).Take(size)).ToArray() : [];
        return new(items, total, number, size);
    }

    private static IOrderedQueryable<CredentialEvidenceEntity> OrderedSummaryRows(HoneypotDbContext db, long now) =>
        db.Set<CredentialEvidenceEntity>().AsNoTracking().Where(row => row.RetentionUntilUtcTicks > now)
            .OrderByDescending(row => row.CapturedAtUtcTicks).ThenBy(row => row.ArtifactId);

    // 摘要只读取所需字段，分页时不加载其余有效行、密文或密码簿指纹。
    private static IQueryable<CredentialEvidenceSummary> ProjectSummaries(IQueryable<CredentialEvidenceEntity> rows) =>
        rows.Select(row => new CredentialEvidenceSummary(row.ArtifactId, row.ConnectionId, row.EventId, row.SourceIp,
            row.AdapterKey, row.MaterialType, Utc(row.CapturedAtUtcTicks), Utc(row.RetentionUntilUtcTicks), false));

    public IReadOnlyCollection<PasswordBookRow> GetPasswordBook()
    {
        using var db = factory.CreateDbContext();
        SetTimeout(db);
        return ProjectPasswordBookRows(OrderPasswordBook(PasswordBookRepresentatives(db, clock.GetUtcNow().UtcTicks)));
    }

    public object GetPasswordBookPage(int? page, int? pageSize, string? keyword = null)
    {
        var (number, size, offset) = QueryPage.Bounds(page, pageSize);
        var now = clock.GetUtcNow().UtcTicks;
        using var db = factory.CreateDbContext();
        SetTimeout(db);
        // 两条查询使用同一读事务，持续采集时列表和总数保持同一快照。
        var connection = (SqliteConnection)db.Database.GetDbConnection();
        db.Database.OpenConnection();
        using var transaction = connection.BeginTransaction(deferred: true);
        using var contextTransaction = db.Database.UseTransaction(transaction);
        var rows = PasswordBookRepresentatives(db, now);
        int total;
        if (keyword?.Trim() is { Length: > 0 } filter)
        {
            var needle = PasswordBookProjection.FoldSearchText(filter);
            // 子串条件只检查代表行。组别计数仍包含匹配组的所有有效尝试。
            rows = rows.Where(row => row.Username.ToLower().Contains(needle) || row.AdapterKey.ToLower().Contains(needle));
            total = rows.Count();
        }
        else
        {
            total = db.Set<CredentialEvidenceEntity>().AsNoTracking()
                .Where(row => row.RetentionUntilUtcTicks > now && row.PasswordBookOccurredAtUtcTicks != null)
                .Select(row => row.PasswordBookFingerprint).Distinct().Count();
        }
        var items = offset < total ? ProjectPasswordBookRows(OrderPasswordBook(rows).Skip((int)offset).Take(size)) : [];
        return new QueryPageResult<PasswordBookRow>(items, total, number, size);
    }

    public async Task ConfirmPasswordBookAttemptAsync(HoneypotDbContext db, InteractionEvent acceptedEvent,
        CancellationToken cancellationToken, DateTimeOffset acceptedAtUtc)
    {
        if (!OverviewActivityProjection.IsAuthenticationFailure(acceptedEvent) || acceptedEvent.CaptureTruncated ||
            string.IsNullOrEmpty(acceptedEvent.Username) || string.IsNullOrEmpty(acceptedEvent.CredentialArtifactId))
            return;

        var entries = db.Set<CredentialEvidenceEntity>();
        var entry = await entries.SingleOrDefaultAsync(row => row.ArtifactId == acceptedEvent.CredentialArtifactId &&
            row.PasswordBookOccurredAtUtcTicks == null && row.RetentionUntilUtcTicks > acceptedAtUtc.UtcTicks,
            cancellationToken);
        if (entry is null || !PasswordBookProjection.IsCandidateMaterialType(entry.MaterialType) ||
            !string.Equals(entry.EventId, acceptedEvent.EventId, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(entry.ConnectionId, acceptedEvent.ConnectionId, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(entry.AdapterKey, acceptedEvent.AdapterKey, StringComparison.OrdinalIgnoreCase) ||
            (acceptedEvent.MaterialType is { } type && !entry.MaterialType.Equals(type, StringComparison.OrdinalIgnoreCase)) ||
            await entries.AnyAsync(row => row.EventId == entry.EventId && row.PasswordBookOccurredAtUtcTicks != null, cancellationToken))
            return;

        // 未确认前只保存加密证据，关闭账号记录时不从证据中产生明文账号索引。
        using var key = keys.Read(mayInitialize: false);
        var plaintext = new byte[entry.Ciphertext.Length];
        PasswordBookProjection.Candidate? candidate;
        try
        {
            Decrypt(entry, ToSummary(entry), key, plaintext);
            candidate = PasswordBookProjection.ReadCandidate(plaintext, entry.AdapterKey, entry.MaterialType, key.FingerprintKey);
        }
        finally { CryptographicOperations.ZeroMemory(plaintext); }
        if (candidate is null || !candidate.IsCompatibleWith(acceptedEvent.AuthenticationMethod) ||
            !string.Equals(candidate.EventUsername, acceptedEvent.Username, StringComparison.Ordinal)) return;

        // 由事件写入者提交此次更新。事件事务回滚时，证据仍在，但不进入密码簿。
        entry.PasswordBookFingerprint = candidate.Fingerprint;
        entry.PasswordBookUsername = acceptedEvent.Username;
        entry.PasswordBookOccurredAtUtcTicks = acceptedEvent.OccurredAtUtc.UtcTicks;
    }

    private static IQueryable<PasswordBookIndexRow> PasswordBookRepresentatives(HoneypotDbContext db, long now) =>
        // 对每个组合选出仍有效的最新代表证据，时间相同时按编号稳定排序。
        db.Database.SqlQuery<PasswordBookIndexRow>($"""
            WITH ranked AS (
                SELECT PasswordBookUsername AS Username, AdapterKey, ArtifactId,
                    PasswordBookOccurredAtUtcTicks AS LastUsedAtUtcTicks,
                    COUNT(*) OVER (PARTITION BY PasswordBookFingerprint) AS AuthenticationCount,
                    ROW_NUMBER() OVER (PARTITION BY PasswordBookFingerprint
                        ORDER BY PasswordBookOccurredAtUtcTicks DESC, ArtifactId) AS rank
                FROM credential_evidence
                WHERE RetentionUntilUtcTicks > {now} AND PasswordBookOccurredAtUtcTicks IS NOT NULL
            )
            SELECT Username, AdapterKey, ArtifactId, LastUsedAtUtcTicks, AuthenticationCount
            FROM ranked WHERE rank = 1
            """);

    private static IOrderedQueryable<PasswordBookIndexRow> OrderPasswordBook(IQueryable<PasswordBookIndexRow> rows) =>
        rows.OrderByDescending(row => row.LastUsedAtUtcTicks).ThenBy(row => row.ArtifactId);

    private static PasswordBookRow[] ProjectPasswordBookRows(IQueryable<PasswordBookIndexRow> rows) => rows.AsEnumerable()
        .Select(row => new PasswordBookRow(row.Username, row.AdapterKey,
            row.AuthenticationCount, Utc(row.LastUsedAtUtcTicks), row.ArtifactId)).ToArray();

    private static CredentialEvidenceEntity Encrypt(CredentialEvidenceSummary summary, string content, int contentBytes,
        CredentialEvidenceKeys.KeyMaterial key)
    {
        var nonce = RandomNumberGenerator.GetBytes(12);
        var tag = new byte[16];
        var ciphertext = new byte[contentBytes];
        var plaintext = Encoding.UTF8.GetBytes(content);
        try
        {
            using var aes = new AesGcm(key.EncryptionKey, tag.Length);
            aes.Encrypt(nonce, plaintext, ciphertext, tag, AssociatedData(summary, key.Id));
            return new CredentialEvidenceEntity
            {
                ArtifactId = summary.CredentialArtifactId, ConnectionId = summary.ConnectionId, EventId = summary.EventId,
                SourceIp = summary.SourceIp, AdapterKey = summary.AdapterKey, MaterialType = summary.MaterialType,
                CapturedAtUtcTicks = summary.CapturedAtUtc.UtcTicks, RetentionUntilUtcTicks = summary.RetentionUntilUtc.UtcTicks,
                KeyId = key.Id, ContentBytes = contentBytes, Nonce = nonce, Tag = tag, Ciphertext = ciphertext,
            };
        }
        finally { CryptographicOperations.ZeroMemory(plaintext); }
    }

    private static void Decrypt(CredentialEvidenceEntity row, CredentialEvidenceSummary summary,
        CredentialEvidenceKeys.KeyMaterial key, Span<byte> plaintext)
    {
        if (!string.Equals(row.KeyId, key.Id, StringComparison.Ordinal))
            throw new CryptographicException("CREDENTIAL_EVIDENCE_KEY_MISMATCH");
        using var aes = new AesGcm(key.EncryptionKey, row.Tag.Length);
        aes.Decrypt(row.Nonce, row.Ciphertext, row.Tag, plaintext, AssociatedData(summary, row.KeyId));
    }

    private static CredentialEvidenceSummary ToSummary(CredentialEvidenceEntity row) => new(row.ArtifactId, row.ConnectionId,
        row.EventId, row.SourceIp, row.AdapterKey, row.MaterialType, Utc(row.CapturedAtUtcTicks), Utc(row.RetentionUntilUtcTicks), false);

    private static byte[] AssociatedData(CredentialEvidenceSummary summary, string keyId) => Encoding.UTF8.GetBytes(
        string.Create(CultureInfo.InvariantCulture,
            $"Honeypot.CredentialEvidence.v1\n{keyId}\n{summary.CredentialArtifactId}\n{summary.ConnectionId}\n{summary.EventId}\n{summary.SourceIp}\n{summary.AdapterKey}\n{summary.MaterialType}\n{summary.CapturedAtUtc.UtcTicks}\n{summary.RetentionUntilUtc.UtcTicks}"));

    private static bool ValidMetadata(string value, int maxLength) => value.Length is > 0 &&
        value.Length <= maxLength && !value.Any(char.IsControl);

    internal static DateTimeOffset Utc(long ticks) => new(ticks, TimeSpan.Zero);

    internal static void SetTimeout(HoneypotDbContext db)
    {
        db.Database.SetCommandTimeout(2);
        if (db.Database.GetDbConnection() is SqliteConnection sqlite) sqlite.DefaultTimeout = 2;
    }

    private sealed class PasswordBookIndexRow
    {
        public required string Username { get; init; }
        public required string AdapterKey { get; init; }
        public required string ArtifactId { get; init; }
        public long LastUsedAtUtcTicks { get; init; }
        public int AuthenticationCount { get; init; }
    }
}
