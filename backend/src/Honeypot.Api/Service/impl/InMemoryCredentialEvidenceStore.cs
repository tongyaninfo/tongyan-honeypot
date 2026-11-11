using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using Honeypot.Api.Models;
using Honeypot.Api.Common;
using Honeypot.Shared.Models;

namespace Honeypot.Api.Service.impl;

/// <summary>
/// 开发阶段 AES-GCM 加密证据仓库。密文及进程内密钥均不持久化；重启后不可恢复。
/// 定期销毁过期密文，读取时再次检查留存期限。生产环境仍需受控密钥与持久化。
/// </summary>
public sealed class InMemoryCredentialEvidenceStore : ICredentialEvidenceStore, IDisposable
{
    private sealed record StoredEvidence(CredentialEvidenceSummary Summary, byte[] Nonce, byte[] Tag, byte[] Ciphertext);
    private readonly byte[] _encryptionKey = RandomNumberGenerator.GetBytes(32);
    private readonly ConcurrentDictionary<string, StoredEvidence> _items = new(StringComparer.OrdinalIgnoreCase);
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
        var plaintext = Encoding.UTF8.GetBytes(content);
        try
        {
            lock (_gate)
            {
                ObjectDisposedException.ThrowIf(_disposed, this);
                PurgeExpired();
                if (_items.Count >= 10000 || plaintext.Length > 4 * 1024 * 1024 || _storedBytes + plaintext.Length > MaxStoredBytes)
                    throw new InvalidOperationException("CREDENTIAL_STORE_CAPACITY_EXCEEDED");
                var artifactId = $"cred-{Guid.NewGuid():N}";
                var capturedAt = _clock.GetUtcNow();
                var summary = new CredentialEvidenceSummary(artifactId, connectionId, eventId, sourceIp, adapterKey,
                    materialType, capturedAt, capturedAt.AddDays(retentionDays), false);
                var nonce = RandomNumberGenerator.GetBytes(12);
                var ciphertext = new byte[plaintext.Length];
                var tag = new byte[16];
                using var aes = new AesGcm(_encryptionKey, tag.Length);
                // 关联元数据同时参加认证，避免密文被错误关联到其它事件。
                aes.Encrypt(nonce, plaintext, ciphertext, tag, AssociatedData(summary));
                _items[artifactId] = new(summary, nonce, tag, ciphertext);
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
        finally { CryptographicOperations.ZeroMemory(plaintext); }
    }

    public CredentialEvidenceView? Get(string credentialArtifactId)
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            PurgeExpired();
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
            PurgeExpired();
            return _items.Values.Select(item => item.Summary).OrderByDescending(item => item.CapturedAtUtc).ToArray();
        }
    }

    private static byte[] AssociatedData(CredentialEvidenceSummary summary) =>
        Encoding.UTF8.GetBytes($"{summary.CredentialArtifactId}\n{summary.ConnectionId}\n{summary.EventId}\n{summary.MaterialType}");

    private void PurgeExpired()
    {
        lock (_gate)
        {
            if (_disposed) return;
            var now = _clock.GetUtcNow();
            foreach (var pair in _items)
            {
                if (pair.Value.Summary.RetentionUntilUtc <= now && _items.TryRemove(pair.Key, out var expired))
                {
                    _storedBytes -= expired.Ciphertext.Length;
                    CryptographicOperations.ZeroMemory(expired.Ciphertext);
                }
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
            CryptographicOperations.ZeroMemory(_encryptionKey);
        }
    }
}
