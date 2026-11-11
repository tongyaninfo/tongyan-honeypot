namespace Honeypot.Protocol.Abstractions.Models;

/// <summary>
/// 协议拟真人格配置。运行时会在会话创建时复制快照，避免热重载影响既有连接。
/// </summary>
public sealed record ServiceProfile
{
    public required string ProfileId { get; init; }
    public required string AdapterKey { get; init; }
    public string AdapterVersion { get; init; } = "1";
    public string AdvertisedProduct { get; init; } = "Honeypot Service";
    public string AdvertisedVersion { get; init; } = "0.1.0";
    /// <summary>对外呈现的主机名；为空时由适配器按协议生成拟真默认值。</summary>
    public string? AdvertisedHostName { get; init; }
    public string FidelityLevel { get; init; } = "L1";
    public string AuthMode { get; init; } = "AlwaysFail";
    /// <summary>MySQL 宣告的认证插件；不影响其它协议。仅用于协议协商，不验证密码。</summary>
    public string MySqlAuthenticationPlugin { get; init; } = "caching_sha2_password";
    /// <summary>PostgreSQL 认证人格；默认保持现代客户端常用的 SCRAM。</summary>
    public string PostgreSqlAuthenticationMethod { get; init; } = "scram-sha-256";
    /// <summary>Oracle 协议服务名，与本平台实例显示名分别管理。</summary>
    public string OracleServiceName { get; init; } = "ORCL";
    /// <summary>InfluxDB API 人格，仅支持 v1/v2，不将 Token 冒充用户密码。</summary>
    public string InfluxDbApiVersion { get; init; } = "v2";
    public bool RecordUsername { get; init; } = true;
    public bool RecordPassword { get; init; } = true;
    public bool StoreCredentialEvidence { get; init; } = true;
    public string? CredentialEvidenceEncryptionKeyRef { get; init; }
    public int CredentialEvidenceRetentionDays { get; init; } = 30;
    public int MaxAuthenticationAttempts { get; init; } = 3;
    public TimeSpan HandshakeTimeout { get; init; } = TimeSpan.FromSeconds(15);
    public TimeSpan IdleTimeout { get; init; } = TimeSpan.FromSeconds(60);
    public int MaxFrameBytes { get; init; } = 64 * 1024;
    public long MaxSessionBytes { get; init; } = 4 * 1024 * 1024;
}
