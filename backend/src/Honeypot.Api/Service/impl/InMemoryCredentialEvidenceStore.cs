using System.Security.Cryptography;
using System.Text;
using Honeypot.Api.Models;
using Honeypot.Api.Common;
using Honeypot.Protocol.Abstractions.Models;
using Honeypot.Shared.Models;

namespace Honeypot.Api.Service.impl;

/// <summary>
/// 开发阶段 AES-GCM 加密证据仓库。密文及进程内密钥均不持久化；重启后不可恢复。
/// 定期销毁过期密文，读取时再次检查留存期限。生产环境仍需受控密钥与持久化。
/// </summary>
public sealed class InMemoryCredentialEvidenceStore : ICredentialEvidenceStore, IDisposable
{
    private sealed record StoredEvidence(CredentialEvidenceSummary Summary, byte[] Nonce, byte[] Tag, byte[] Ciphertext,
        PasswordBookProjection.Candidate? Candidate)
    {
        public PasswordBookAttempt? ConfirmedAttempt { get; set; }
    }

    private sealed record PasswordBookAttempt(string Username, string AdapterKey, DateTimeOffset OccurredAtUtc, string ArtifactId);

    private static readonly IComparer<PasswordBookAttempt> MostRecentFirst = Comparer<PasswordBookAttempt>.Create((first, second) =>
    {
        var byTime = second!.OccurredAtUtc.CompareTo(first!.OccurredAtUtc);
        return byTime != 0 ? byTime : StringComparer.Ordinal.Compare(first.ArtifactId, second.ArtifactId);
    });

    private readonly byte[] _encryptionKey = RandomNumberGenerator.GetBytes(32);
    private readonly byte[] _passwordBookKey = RandomNumberGenerator.GetBytes(32);
    private readonly Dictionary<string, StoredEvidence> _items = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, SortedSet<PasswordBookAttempt>> _passwordBookGroups = new(StringComparer.Ordinal);
    private readonly HashSet<string> _confirmedEventIds = new(StringComparer.OrdinalIgnoreCase);
    private readonly PriorityQueue<string, DateTimeOffset> _expirations = new();
    private readonly TimeProvider _clock;
    private readonly ISyslogPublisher? _syslog;
    private readonly ITimer _expirationTimer;
    private readonly object _gate = new();
    private long _storedBytes;
    private bool _disposed;
    private const long MaxStoredBytes = 64 * 1024 * 1024;

    public InMemoryCredentialEvidenceStore(TimeProvider? clock = null, ISyslogPublisher? syslog = null)
    {
        _clock = clock ?? TimeProvider.System;
        _syslog = syslog;
        _expirationTimer = _clock.CreateTimer(_ => PurgeExpired(), null, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(1));
    }

    public Task<CredentialEvidenceSummary> SaveAsync(string connectionId, string eventId, string sourceIp,
        string adapterKey, string materialType, string content, int retentionDays, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (retentionDays is < 1 or > 3650) throw new ArgumentOutOfRangeException(nameof(retentionDays));
        var byteCount = Encoding.UTF8.GetByteCount(content);
        try
        {
            lock (_gate)
            {
                ObjectDisposedException.ThrowIf(_disposed, this);
                var capturedAt = _clock.GetUtcNow();
                PurgeExpiredLocked(capturedAt);
                if (byteCount > 4 * 1024 * 1024 || _storedBytes + byteCount > MaxStoredBytes)
                    throw new InvalidOperationException("CREDENTIAL_STORE_CAPACITY_EXCEEDED");
                var artifactId = $"cred-{Guid.NewGuid():N}";
                var summary = new CredentialEvidenceSummary(artifactId, connectionId, eventId, sourceIp, adapterKey,
                    materialType, capturedAt, capturedAt.AddDays(retentionDays), false);
                var nonce = RandomNumberGenerator.GetBytes(12);
                var ciphertext = new byte[byteCount];
                var tag = new byte[16];
                using var aes = new AesGcm(_encryptionKey, tag.Length);
                // 关联元数据同时参加认证，避免密文被错误关联到其它事件。
                var plaintext = Encoding.UTF8.GetBytes(content);
                PasswordBookProjection.Candidate? candidate;
                try
                {
                    aes.Encrypt(nonce, plaintext, ciphertext, tag, AssociatedData(summary));
                    candidate = PasswordBookProjection.ReadCandidate(plaintext, adapterKey, materialType, _passwordBookKey);
                }
                finally { CryptographicOperations.ZeroMemory(plaintext); }
                _items[artifactId] = new(summary, nonce, tag, ciphertext, candidate);
                _expirations.Enqueue(artifactId, summary.RetentionUntilUtc);
                _storedBytes += ciphertext.Length;
                SyslogInteractionProjection.PublishSafely(_syslog, "honeypot-evidence", "EVIDENCE_CAPTURED", SyslogSeverity.Informational,
                    new Dictionary<string, object?> { ["credentialArtifactId"] = artifactId, ["eventId"] = eventId,
                        ["connectionId"] = connectionId, ["adapterKey"] = adapterKey, ["materialType"] = materialType,
                        ["outcome"] = "captured" });
                return Task.FromResult(summary);
            }
        }
        catch (Exception)
        {
            SyslogInteractionProjection.PublishSafely(_syslog, "honeypot-evidence", "EVIDENCE_CAPTURE_FAILED", SyslogSeverity.Error,
                new Dictionary<string, object?> { ["eventId"] = eventId, ["connectionId"] = connectionId,
                    ["adapterKey"] = adapterKey, ["errorCode"] = "EVIDENCE_CAPTURE_FAILED" });
            throw;
        }
    }

    public CredentialEvidenceView? Get(string credentialArtifactId)
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            PurgeExpiredLocked(_clock.GetUtcNow());
            if (!_items.TryGetValue(credentialArtifactId, out var item)) return null;
            var plaintext = new byte[item.Ciphertext.Length];
            try
            {
                using var aes = new AesGcm(_encryptionKey, item.Tag.Length);
                aes.Decrypt(item.Nonce, item.Ciphertext, item.Tag, plaintext, AssociatedData(item.Summary));
                return new(item.Summary, Encoding.UTF8.GetString(plaintext));
            }
            finally { CryptographicOperations.ZeroMemory(plaintext); }
        }
    }

    public IReadOnlyCollection<CredentialEvidenceSummary> GetAll()
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            PurgeExpiredLocked(_clock.GetUtcNow());
            return _items.Values.Select(item => item.Summary).OrderByDescending(item => item.CapturedAtUtc).ToArray();
        }
    }

    public void ConfirmPasswordBookAttempt(InteractionEvent acceptedEvent)
    {
        if (!OverviewActivityProjection.IsAuthenticationFailure(acceptedEvent) || acceptedEvent.CaptureTruncated ||
            string.IsNullOrEmpty(acceptedEvent.Username) || string.IsNullOrEmpty(acceptedEvent.CredentialArtifactId))
            return;

        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            PurgeExpiredLocked(_clock.GetUtcNow());
            if (!_items.TryGetValue(acceptedEvent.CredentialArtifactId, out var item) || item.Candidate is not { } candidate ||
                item.Summary.Truncated || !candidate.IsCompatibleWith(acceptedEvent.AuthenticationMethod) ||
                !string.Equals(candidate.EventUsername, acceptedEvent.Username, StringComparison.Ordinal) ||
                !string.Equals(item.Summary.EventId, acceptedEvent.EventId, StringComparison.OrdinalIgnoreCase) ||
                !string.Equals(item.Summary.ConnectionId, acceptedEvent.ConnectionId, StringComparison.OrdinalIgnoreCase) ||
                !string.Equals(item.Summary.AdapterKey, acceptedEvent.AdapterKey, StringComparison.OrdinalIgnoreCase) ||
                (acceptedEvent.MaterialType is { } type && !item.Summary.MaterialType.Equals(type, StringComparison.OrdinalIgnoreCase)) ||
                !_confirmedEventIds.Add(acceptedEvent.EventId))
                return;

            // 存证先于事件确认，只有事件成功入库且两者关联一致才计入组合。
            if (!_passwordBookGroups.TryGetValue(candidate.Fingerprint, out var group))
                _passwordBookGroups.Add(candidate.Fingerprint, group = new(MostRecentFirst));
            var attempt = new PasswordBookAttempt(acceptedEvent.Username, item.Summary.AdapterKey,
                acceptedEvent.OccurredAtUtc.ToUniversalTime(), item.Summary.CredentialArtifactId);
            group.Add(attempt);
            item.ConfirmedAttempt = attempt;
        }
    }

    public IReadOnlyCollection<PasswordBookRow> GetPasswordBook()
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            PurgeExpiredLocked(_clock.GetUtcNow());
            return _passwordBookGroups.Values.Select(group =>
            {
                var latest = group.Min!;
                return new PasswordBookRow(latest.Username, latest.AdapterKey, group.Count, latest.OccurredAtUtc, latest.ArtifactId);
            }).ToArray();
        }
    }

    private static byte[] AssociatedData(CredentialEvidenceSummary summary) =>
        Encoding.UTF8.GetBytes($"{summary.CredentialArtifactId}\n{summary.ConnectionId}\n{summary.EventId}\n{summary.MaterialType}");

    private void PurgeExpired()
    {
        lock (_gate)
        {
            if (!_disposed) PurgeExpiredLocked(_clock.GetUtcNow());
        }
    }

    private void PurgeExpiredLocked(DateTimeOffset now)
    {
        // 取证路径只处理已经到期的证据，不逐笔扫描所有活跃密文。
        while (_expirations.TryPeek(out var artifactId, out var expires) && expires <= now)
        {
            _expirations.Dequeue();
            if (!_items.Remove(artifactId, out var expired)) continue;
            _storedBytes -= expired.Ciphertext.Length;
            CryptographicOperations.ZeroMemory(expired.Ciphertext);
            if (expired.ConfirmedAttempt is { } attempt && expired.Candidate is { } candidate)
            {
                _confirmedEventIds.Remove(expired.Summary.EventId);
                var group = _passwordBookGroups[candidate.Fingerprint];
                group.Remove(attempt);
                if (group.Count == 0) _passwordBookGroups.Remove(candidate.Fingerprint);
            }
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed) return;
            _disposed = true;
            _expirationTimer.Dispose();
            foreach (var item in _items.Values) CryptographicOperations.ZeroMemory(item.Ciphertext);
            _items.Clear();
            _expirations.Clear();
            _passwordBookGroups.Clear();
            _confirmedEventIds.Clear();
            CryptographicOperations.ZeroMemory(_encryptionKey);
            CryptographicOperations.ZeroMemory(_passwordBookKey);
        }
    }
}
