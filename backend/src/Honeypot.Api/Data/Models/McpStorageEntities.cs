namespace Honeypot.Api.Data.Models;

public sealed class McpSettingsEntity
{
    public const int SingletonId = 1;
    public const int DefaultRetentionDays = 30;
    public int Id { get; set; }
    public bool Enabled { get; set; }
    public int AuditRetentionDays { get; set; }
    public long? UpdatedUnixMs { get; set; }
    public string? UpdatedBy { get; set; }
}

public sealed class McpApiKeyEntity
{
    public required string Id { get; set; }
    public required string Prefix { get; set; }
    // 只保存随机密钥摘要，既不能从列表读回，也不能用于直接鉴权。
    public required byte[] SecretDigest { get; set; }
    public required string Name { get; set; }
    public required string Mode { get; set; }
    public required string PermissionsJson { get; set; }
    public required string InstanceGrantsJson { get; set; }
    public required string CreatedBy { get; set; }
    public long CreatedUnixMs { get; set; }
    public long? ExpiresUnixMs { get; set; }
    public long? RevokedUnixMs { get; set; }
    public long? LastUsedUnixMs { get; set; }
}

public sealed class McpCallAuditEntity
{
    public required string Id { get; set; }
    public long OccurredUnixMs { get; set; }
    // 快照不依赖外键，删除已吊销 Key 后历史仍可核对。
    public string? KeyId { get; set; }
    public string? KeyName { get; set; }
    public string? KeyPrefix { get; set; }
    public string? Tool { get; set; }
    public string? McpMethod { get; set; }
    public string? SourceIp { get; set; }
    public required string HttpMethod { get; set; }
    public int? HttpStatus { get; set; }
    public required string Result { get; set; }
    public long? DurationMs { get; set; }
    public required string DetailsJson { get; set; }
}
