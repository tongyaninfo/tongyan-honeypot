using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Honeypot.Api.Data;
using Honeypot.Api.Data.Models;
using Honeypot.Api.Models;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;

namespace Honeypot.Api.Service.impl;

public sealed partial class SqliteMcpStore(
    IDbContextFactory<HoneypotDbContext> dbFactory, IResourceIdGenerator ids, TimeProvider clock, McpAuditHealth health)
    : IMcpStore
{
    private const string KeyMarker = "hp_mcp_";
    private const int KeyPrefixLength = 23;
    private const int KeySecretLength = 43;
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public async Task<McpSettings> GetSettingsAsync(CancellationToken cancellationToken = default)
    {
        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
        return Settings(await SettingsQuery(db).AsNoTracking().SingleAsync(cancellationToken));
    }

    public async Task<McpSettings> UpdateSettingsAsync(McpUpdateSettingsRequest request, string userId, CancellationToken cancellationToken)
    {
        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
        var now = clock.GetUtcNow().ToUnixTimeMilliseconds();
        await SettingsQuery(db).ExecuteUpdateAsync(set => set
            .SetProperty(row => row.Enabled, row => request.Enabled ?? row.Enabled)
            .SetProperty(row => row.AuditRetentionDays, row => request.AuditRetentionDays ?? row.AuditRetentionDays)
            .SetProperty(row => row.UpdatedUnixMs, (long?)now)
            .SetProperty(row => row.UpdatedBy, userId), cancellationToken);
        return Settings(await SettingsQuery(db).AsNoTracking().SingleAsync(cancellationToken));
    }

    public async Task<McpPage<McpKeySummary>> GetKeysAsync(int page, int pageSize, CancellationToken cancellationToken)
    {
        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
        var query = db.Set<McpApiKeyEntity>().AsNoTracking();
        var total = await query.CountAsync(cancellationToken);
        var rows = await query.OrderByDescending(row => row.CreatedUnixMs).ThenByDescending(row => row.Id)
            .Skip((page - 1) * pageSize).Take(pageSize).ToListAsync(cancellationToken);
        var now = clock.GetUtcNow();
        return new(rows.Select(row => Summary(Key(row), now)).ToArray(), total, page, pageSize);
    }

    public async Task<McpCreatedKey> CreateKeyAsync(
        string name, string mode, string[] permissions, McpInstanceGrant[] grants, DateTimeOffset? expiresAtUtc, string userId,
        CancellationToken cancellationToken)
    {
        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
        var prefix = KeyMarker + Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(8));
        var secret = WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));
        var now = clock.GetUtcNow();
        var row = new McpApiKeyEntity
        {
            Id = ids.NewId(), Prefix = prefix, SecretDigest = Digest(secret.AsSpan()),
            Name = name, Mode = mode, PermissionsJson = JsonSerializer.Serialize(permissions, Json),
            InstanceGrantsJson = JsonSerializer.Serialize(grants, Json), CreatedBy = userId,
            CreatedUnixMs = now.ToUnixTimeMilliseconds(), ExpiresUnixMs = expiresAtUtc?.ToUnixTimeMilliseconds(),
        };
        db.Add(row);
        await db.SaveChangesAsync(cancellationToken);
        return new(Summary(Key(row), now), $"{prefix}.{secret}");
    }

    public async Task<McpAuthenticationResult> AuthenticateAsync(string token, CancellationToken cancellationToken = default)
    {
        if (!IsKeyToken(token)) return new("INVALID_API_KEY", null);
        var prefix = token[..KeyPrefixLength];
        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
        var row = await db.Set<McpApiKeyEntity>().AsNoTracking().SingleOrDefaultAsync(item => item.Prefix == prefix, cancellationToken);
        if (row is null || !CryptographicOperations.FixedTimeEquals(row.SecretDigest, Digest(token.AsSpan(KeyPrefixLength + 1))))
            return new("INVALID_API_KEY", null);
        var key = Key(row);
        if (key.RevokedAtUtc.HasValue) return new("API_KEY_REVOKED", key);
        if (key.ExpiresAtUtc <= clock.GetUtcNow()) return new("API_KEY_EXPIRED", key);
        return new("OK", key);
    }

    public async Task TouchKeyAsync(string id, CancellationToken cancellationToken = default)
    {
        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
        var now = clock.GetUtcNow().ToUnixTimeMilliseconds();
        await db.Set<McpApiKeyEntity>().Where(row => row.Id == id && (row.LastUsedUnixMs == null || row.LastUsedUnixMs < now))
            .ExecuteUpdateAsync(set => set.SetProperty(row => row.LastUsedUnixMs, (long?)now), cancellationToken);
    }

    public async Task<bool> RevokeKeyAsync(string id, CancellationToken cancellationToken)
    {
        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
        var query = db.Set<McpApiKeyEntity>().Where(row => row.Id == id);
        var now = clock.GetUtcNow().ToUnixTimeMilliseconds();
        return await query.Where(row => row.RevokedUnixMs == null)
            .ExecuteUpdateAsync(set => set.SetProperty(row => row.RevokedUnixMs, (long?)now), cancellationToken) > 0
            || await query.AnyAsync(cancellationToken);
    }

    public async Task<string> DeleteKeyAsync(string id, CancellationToken cancellationToken)
    {
        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
        var query = db.Set<McpApiKeyEntity>().Where(row => row.Id == id);
        if (await query.Where(row => row.RevokedUnixMs != null).ExecuteDeleteAsync(cancellationToken) > 0) return "OK";
        return await query.AnyAsync(cancellationToken) ? "MCP_KEY_REVOKE_REQUIRED" : "MCP_KEY_NOT_FOUND";
    }

    public static bool IsKeyToken(string token)
    {
        if (token.Length != KeyPrefixLength + 1 + KeySecretLength || token[KeyPrefixLength] != '.' ||
            !token.StartsWith(KeyMarker, StringComparison.Ordinal)) return false;
        foreach (var c in token.AsSpan(KeyMarker.Length, KeyPrefixLength - KeyMarker.Length))
            if (c is not (>= '0' and <= '9' or >= 'a' and <= 'f')) return false;
        foreach (var c in token.AsSpan(KeyPrefixLength + 1))
            if (!char.IsAsciiLetterOrDigit(c) && c is not ('-' or '_')) return false;
        return true;
    }

    private static byte[] Digest(ReadOnlySpan<char> secret)
    {
        Span<byte> buffer = stackalloc byte[KeySecretLength];
        Encoding.ASCII.GetBytes(secret, buffer);
        var digest = SHA256.HashData(buffer);
        CryptographicOperations.ZeroMemory(buffer);
        return digest;
    }

    private static IQueryable<McpSettingsEntity> SettingsQuery(HoneypotDbContext db) =>
        db.Set<McpSettingsEntity>().Where(row => row.Id == McpSettingsEntity.SingletonId);
    private McpSettings Settings(McpSettingsEntity row) =>
        new(row.Enabled, row.AuditRetentionDays, health.IsAvailable, FromUnix(row.UpdatedUnixMs), row.UpdatedBy, health.DroppedCount);
    private static McpApiKey Key(McpApiKeyEntity row) => new(row.Id, row.Prefix, row.Name, row.Mode,
        JsonSerializer.Deserialize<string[]>(row.PermissionsJson, Json) ?? [],
        JsonSerializer.Deserialize<McpInstanceGrant[]>(row.InstanceGrantsJson, Json) ?? [],
        DateTimeOffset.FromUnixTimeMilliseconds(row.CreatedUnixMs), FromUnix(row.ExpiresUnixMs), FromUnix(row.RevokedUnixMs),
        FromUnix(row.LastUsedUnixMs));
    private static McpKeySummary Summary(McpApiKey key, DateTimeOffset now) => new(key.Id, key.Name, key.Prefix, key.Mode, key.PermissionIds,
        key.InstanceGrants.Select(grant => grant.InstanceId).ToArray(), key.CreatedAtUtc, key.ExpiresAtUtc, key.RevokedAtUtc,
        key.LastUsedAtUtc, key.RevokedAtUtc.HasValue ? "Revoked" : key.ExpiresAtUtc <= now ? "Expired" : "Active");
    private static DateTimeOffset? FromUnix(long? timestamp) =>
        timestamp is { } value ? DateTimeOffset.FromUnixTimeMilliseconds(value) : null;
}
