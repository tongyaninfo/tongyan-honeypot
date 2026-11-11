namespace Honeypot.Api.Data.Models;

/// <summary>冻结的报表及任务键；同一自动周期只能创建一次任务。</summary>
public sealed class ReportSnapshotEntity
{
    public string Id { get; set; } = string.Empty;
    public string PeriodKind { get; set; } = string.Empty;
    public string TaskKey { get; set; } = string.Empty;
    public long PeriodStartUnixMs { get; set; }
    public long PeriodEndUnixMs { get; set; }
    public long CreatedUnixMs { get; set; }
    public string ReportJson { get; set; } = string.Empty;
    public string TemplateVersion { get; set; } = "1";
}

/// <summary>每位收件人独立投递，正文在入队时冻结，不随报表数据变化。</summary>
public sealed class EmailDeliveryEntity
{
    public string Id { get; set; } = string.Empty;
    public string? ReportSnapshotId { get; set; }
    public string Kind { get; set; } = string.Empty;
    public string Recipient { get; set; } = string.Empty;
    public string RecipientKey { get; set; } = string.Empty;
    public string DeduplicationKey { get; set; } = string.Empty;
    public string MessageId { get; set; } = string.Empty;
    public string Subject { get; set; } = string.Empty;
    public string HtmlBody { get; set; } = string.Empty;
    public string TextBody { get; set; } = string.Empty;
    public string Status { get; set; } = "Pending";
    public int AttemptCount { get; set; }
    public int AutomaticAttemptCount { get; set; }
    public long CreatedUnixMs { get; set; }
    public long UpdatedUnixMs { get; set; }
    public long? NextAttemptUnixMs { get; set; }
    public long? AcceptedUnixMs { get; set; }
    public long? LeaseExpiresUnixMs { get; set; }
    public string? LastErrorCode { get; set; }
    public string? LastErrorMessage { get; set; }
    public string RequestedBy { get; set; } = string.Empty;
}

/// <summary>仅保存受控结果码，绝不保存 SMTP 服务端回显或账号授权码。</summary>
public sealed class EmailDeliveryAttemptEntity
{
    public string Id { get; set; } = string.Empty;
    public string DeliveryId { get; set; } = string.Empty;
    public int Number { get; set; }
    public long StartedUnixMs { get; set; }
    public long? CompletedUnixMs { get; set; }
    public string Status { get; set; } = "Sending";
    public string? ErrorCode { get; set; }
    public string? ErrorMessage { get; set; }
}
