namespace Honeypot.Api.Models;

public static class McpAccess
{
    public const string ReadOnly = "ReadOnly";
    public const string ReadWrite = "ReadWrite";
}

public static class McpAuditResult
{
    public const string Pending = "Pending";
    public const string Success = "Success";
    public const string ToolError = "ToolError";
    public const string ProtocolError = "ProtocolError";
    public const string Denied = "Denied";
    public const string RateLimited = "RateLimited";
    public const string Unavailable = "Unavailable";
    public const string Unknown = "Unknown";

    public static bool IsKnown(string result) => result is Pending or Success or ToolError or ProtocolError
        or Denied or RateLimited or Unavailable or Unknown;
}

public sealed record McpSettings(
    bool Enabled, int AuditRetentionDays, bool AuditAvailable, DateTimeOffset? UpdatedAtUtc, string? UpdatedBy, long AuditDroppedCount);
public sealed record McpUpdateSettingsRequest(bool? Enabled, int? AuditRetentionDays);
public sealed record McpPage<T>(IReadOnlyList<T> Items, int Total, int Page, int PageSize);
public sealed record McpPermission(string Id, string Label, string Description, string Access, bool RequiresInstanceScope);
public sealed record McpPermissionGroup(string Id, string Label, IReadOnlyList<McpPermission> Tools);
public sealed record McpGrantableInstance(string Id, string Name, string AdapterKey);
public sealed record McpPermissions(IReadOnlyList<McpPermissionGroup> Groups, IReadOnlyList<McpGrantableInstance> Instances);

public sealed record McpInstanceGrant(string InstanceId, string BindingFingerprint);
public sealed record McpApiKey(
    string Id, string Prefix, string Name, string Mode, string[] PermissionIds, McpInstanceGrant[] InstanceGrants,
    DateTimeOffset CreatedAtUtc, DateTimeOffset? ExpiresAtUtc, DateTimeOffset? RevokedAtUtc, DateTimeOffset? LastUsedAtUtc);
public sealed record McpAuthenticationResult(string Code, McpApiKey? Key);
public sealed record McpKeySummary(
    string Id, string Name, string Prefix, string Access, string[] PermissionIds, string[] InstanceIds,
    DateTimeOffset CreatedAtUtc, DateTimeOffset? ExpiresAtUtc, DateTimeOffset? RevokedAtUtc, DateTimeOffset? LastUsedAtUtc, string Status);
public sealed record McpCreateKeyRequest(
    string? Name, string? Access, string[]? PermissionIds, string[]? InstanceIds, string? ExpiresAtUtc);
public sealed record McpCreatedKey(McpKeySummary Key, string Secret);

/// <summary>由传输层筛选并限制大小后交给持久化，详情不进入普通日志。</summary>
public sealed record McpAuditEntry
{
    public required DateTimeOffset OccurredAtUtc { get; init; }
    public required string HttpMethod { get; init; }
    public required string Path { get; init; }
    public required string Result { get; init; }
    public string? SourceIp { get; init; }
    public string? ClientName { get; init; }
    public string? McpMethod { get; init; }
    public string? ProtocolVersion { get; init; }
    public string? RequestId { get; init; }
    public string? TraceId { get; init; }
    public string? KeyId { get; init; }
    public string? KeyName { get; init; }
    public string? KeyPrefix { get; init; }
    public string? ToolName { get; init; }
    public int? HttpStatus { get; init; }
    public string? ErrorCode { get; init; }
    public string? ErrorMessage { get; init; }
    public long? ElapsedMs { get; init; }
    public long? RequestBytes { get; init; }
    public long? ResponseBytes { get; init; }
    public string? RequestHeaders { get; init; }
    public string? RequestParameters { get; init; }
    public string? ResponseHeaders { get; init; }
    public string? ResponseBody { get; init; }
    public string? CaptureNote { get; init; }
    public string? RequestBodyOmittedReason { get; init; }
    public string? ResponseBodyOmittedReason { get; init; }
}

public record McpAuditSummary(
    string Id, DateTimeOffset OccurredAtUtc, string? KeyId, string? KeyName, string? KeyPrefix, string? Tool,
    string? SourceIp, string HttpMethod, string? McpMethod, int? HttpStatus, string Result, long? DurationMs);

public sealed record McpAuditDetails(
    string Id, DateTimeOffset OccurredAtUtc, string? KeyId, string? KeyName, string? KeyPrefix, string? Tool,
    string? SourceIp, string HttpMethod, string? McpMethod, int? HttpStatus, string Result, long? DurationMs, string Path,
    string? Client, string? ProtocolVersion, string? RequestId, string? TraceId,
    string? ErrorCode, string? ErrorMessage, long? RequestBytes, long? ResponseBytes, string? RequestHeaders,
    string? RequestParams, string? ResponseHeaders, string? ResponseBody, string? CaptureNote,
    string? RequestBodyOmittedReason, string? ResponseBodyOmittedReason)
    : McpAuditSummary(Id, OccurredAtUtc, KeyId, KeyName, KeyPrefix, Tool, SourceIp, HttpMethod, McpMethod, HttpStatus, Result, DurationMs);

public sealed record McpAuditFilter(
    int Page, int PageSize, string? KeyId, string? Tool, string? SourceIp, string? Result,
    DateTimeOffset? FromUtc, DateTimeOffset? ToUtc);
