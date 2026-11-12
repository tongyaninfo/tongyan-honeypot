namespace Honeypot.Shared.Models;

/// <summary>通知范围只包含运行报告；读取合同永远不包含 SMTP 授权码。</summary>
public sealed record NotificationSettings
{
    public bool Enabled { get; init; }
    public string Host { get; init; } = string.Empty;
    public int Port { get; init; } = 465;
    public bool UseSsl { get; init; } = true;
    public string SecurityMode { get; init; } = "SslOnConnect";
    public string FromEmail { get; init; } = string.Empty;
    public string FromName { get; init; } = "通研 Honeypot";
    public string Username { get; init; } = string.Empty;
    public bool HasCredential { get; init; }
    public int TimeoutSeconds { get; init; } = 15;
    public string[] DefaultRecipients { get; init; } = [];
    public int MaxPerHour { get; init; } = 100;
    public int MaxPerRecipientPerHour { get; init; } = 20;
    public int TestCooldownSeconds { get; init; } = 60;
    public int ResendCooldownSeconds { get; init; } = 60;
    public ReportScheduleSettings[] Schedules { get; init; } =
    [new() { Kind = "Daily" }, new() { Kind = "Weekly" }, new() { Kind = "Monthly" }];
}

/// <summary>日历周期按 Asia/Shanghai 解释；周报固定周一，月报固定每月一日。</summary>
public sealed record ReportScheduleSettings
{
    public string Kind { get; init; } = "Daily";
    public bool Enabled { get; init; }
    public string SendTime { get; init; } = "08:00";
    public string[] Recipients { get; init; } = [];
    public DateTimeOffset? NextRunAtUtc { get; init; }
    public DateTimeOffset? LastRunAtUtc { get; init; }
    public string? LastRunStatus { get; init; }
}

/// <summary>授权码只写；null 或空字符串表示保留已保存的授权码。</summary>
public sealed record UpdateNotificationSettingsRequest(NotificationSettings Settings, string? AuthorizationCode);
public sealed record TestEmailRequest(string Recipient);
public sealed record ReportSendRequest
{
    public string Period { get; init; } = "day";
    public DateTimeOffset? StartAtUtc { get; init; }
    public DateTimeOffset? EndAtUtc { get; init; }
    public string[] Recipients { get; init; } = [];
}

public sealed record NotificationTaskResult(string[] DeliveryIds, string Message);

public sealed record NotificationPage<T>(IReadOnlyList<T> Items, int Total, int Page, int PageSize);

/// <summary>一条记录对应一个收件人；Accepted 只表示 SMTP 服务器已受理。</summary>
public sealed record EmailDeliverySummary
{
    public required string Id { get; init; }
    public required string Kind { get; init; }
    public required string Recipient { get; init; }
    public required string Subject { get; init; }
    public required string Status { get; init; }
    public DateTimeOffset CreatedAtUtc { get; init; }
    public DateTimeOffset? SentAtUtc { get; init; }
    public DateTimeOffset? NextAttemptAtUtc { get; init; }
    public int AttemptCount { get; init; }
    public string? LastErrorCode { get; init; }
    public string? LastErrorMessage { get; init; }
    public string? ReportId { get; init; }
    public DateTimeOffset? PeriodStartAtUtc { get; init; }
    public DateTimeOffset? PeriodEndAtUtc { get; init; }
}

public sealed record EmailDeliveryDetails(
    EmailDeliverySummary Delivery,
    string HtmlBody,
    string TextBody,
    string TemplateVersion,
    IReadOnlyList<EmailDeliveryAttempt> Attempts,
    bool CanRetry);

public sealed record EmailDeliveryAttempt(
    int AttemptNumber,
    DateTimeOffset StartedAtUtc,
    DateTimeOffset? CompletedAtUtc,
    string Outcome,
    string? ErrorCode,
    string? ErrorMessage);

public sealed record EmailDeliveryQuery
{
    public int Page { get; init; } = 1;
    public int PageSize { get; init; } = 20;
    public string? Kind { get; init; }
    public string? Status { get; init; }
    public string? Recipient { get; init; }
    public DateTimeOffset? FromUtc { get; init; }
    public DateTimeOffset? ToUtc { get; init; }
    /// <summary>报告工具只展示报告邮件，不含投递测试。</summary>
    public bool ReportsOnly { get; init; }
}

public sealed record ReportHistoryItem(
    string Id,
    string Kind,
    string Title,
    DateTimeOffset StartAtUtc,
    DateTimeOffset EndAtUtc,
    DateTimeOffset GeneratedAtUtc,
    int RecipientCount);
