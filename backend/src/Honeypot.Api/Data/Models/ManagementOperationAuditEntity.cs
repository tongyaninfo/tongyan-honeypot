namespace Honeypot.Api.Data.Models;

/// <summary>关键管理操作的审计元数据。请求正文、凭据和自由文本不进入此表。</summary>
public sealed class ManagementOperationAuditEntity
{
    public string Id { get; set; } = "";
    public long OccurredAtUnixMs { get; set; }
    public string Operation { get; set; } = "";
    public string? ActorUserId { get; set; }
    public string? ResourceId { get; set; }
    public int? HttpStatus { get; set; }
}
