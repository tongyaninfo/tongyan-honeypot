using Honeypot.Shared.Models;

namespace Honeypot.Api.Models;

public sealed record NotificationScheduleState(ReportScheduleSettings Settings, DateTimeOffset ActivatedAtUtc);
public sealed record DueReportPeriod(DateTimeOffset ScheduledAtUtc, DateTimeOffset StartAtUtc, DateTimeOffset EndAtUtc);

/// <summary>仅限后端传输层使用，禁止直接序列化为 API 响应。</summary>
public sealed record NotificationTransportSettings(bool Enabled, string Host, int Port,
    string SecurityMode, string SenderAddress, string SenderName, string Username,
    string Credential, int TimeoutSeconds);

public sealed record RenderedEmail(string Subject, string HtmlBody, string TextBody, string TemplateVersion);
public sealed record MailTransportMessage(string Recipient, string MessageId, string Subject, string HtmlBody, string TextBody);
public sealed record MailTransportResult(string Status, string? ErrorCode = null, string? ErrorMessage = null)
{
    public static MailTransportResult Accepted { get; } = new("Accepted");
}

public sealed class NotificationException(string code, string message) : Exception(message)
{
    public string Code { get; } = code;
}
