using System.Globalization;
using Honeypot.Api.Models;
using Honeypot.Shared.Models;
using MimeKit;

namespace Honeypot.Api.Common;

public static class NotificationSettingsValidation
{
    public static NotificationSettings Normalize(NotificationSettings input, bool hasCredential)
    {
        if (input is null) throw Invalid("通知配置不能为空。");
        var host = (input.Host ?? string.Empty).Trim();
        if (host.Length > 253 || host.Contains('/') || host.Contains('@') ||
            (host.Length > 0 && Uri.CheckHostName(host) == UriHostNameType.Unknown)) throw Invalid("邮件服务器须为有效主机名或 IP 地址。");
        if (input.Port is < 1 or > 65535) throw Invalid("端口范围为 1–65535。");
        if (input.SecurityMode is not ("SslOnConnect" or "StartTls" or "None") || input.UseSsl != (input.SecurityMode != "None"))
            throw Invalid("SSL/TLS 开关与加密模式不一致。");
        if (input.TimeoutSeconds is < 5 or > 60) throw Invalid("连接超时范围为 5–60 秒。");
        if (input.MaxPerHour is < 1 or > 1000 || input.MaxPerRecipientPerHour is < 1 or > 1000 ||
            input.MaxPerRecipientPerHour > input.MaxPerHour) throw Invalid("发送配额范围为 1–1000，单收件人配额不得超过总配额。");
        if (input.TestCooldownSeconds is < 10 or > 3600 || input.ResendCooldownSeconds is < 10 or > 3600)
            throw Invalid("测试及重发冷却时间范围为 10–3600 秒。");
        var from = (input.FromEmail ?? string.Empty).Trim();
        if (from.Length > 0) from = NormalizeAddress(from);
        var username = (input.Username ?? string.Empty).Trim();
        if (username.Length == 0) username = from;
        var fromName = input.FromName ?? string.Empty;
        if (username.Length > 320 || username.Any(char.IsControl) || fromName.Length > 100 || fromName.Any(char.IsControl))
            throw Invalid("发件名称或账号格式无效。");
        if (input.Enabled && (host.Length == 0 || from.Length == 0 || username.Length == 0 || !hasCredential))
            throw Invalid("启用通知前请填写服务器、发件邮箱、账号和授权码。");
        var recipients = NormalizeRecipients(input.DefaultRecipients);
        if (input.Schedules is null || input.Schedules.Length != 3 || input.Schedules.Any(schedule => schedule is null) ||
            !input.Schedules.Select(schedule => schedule.Kind).Order().SequenceEqual(new[] { "Daily", "Monthly", "Weekly" }))
            throw Invalid("报告计划必须包含日报、周报、月报各一项。");
        var schedules = input.Schedules.Select(schedule =>
        {
            if (!TimeOnly.TryParseExact(schedule.SendTime, "HH:mm", CultureInfo.InvariantCulture, DateTimeStyles.None, out _))
                throw Invalid("发送时间必须使用 HH:mm 格式。");
            var list = NormalizeRecipients(schedule.Recipients);
            if (schedule.Enabled && list.Length == 0 && recipients.Length == 0) throw Invalid("启用报告计划前请配置收件人。");
            return schedule with { Recipients = list, NextRunAtUtc = null, LastRunAtUtc = null, LastRunStatus = null };
        }).ToArray();
        return input with { Host = host, FromEmail = from, Username = username, FromName = fromName.Trim(),
            HasCredential = hasCredential, DefaultRecipients = recipients, Schedules = schedules };
    }

    public static string NormalizeAddress(string address)
    {
        var value = (address ?? string.Empty).Trim();
        if (value.Length is 0 or > 320 || value.Any(char.IsControl) || !MailboxAddress.TryParse(value, out var parsed) ||
            parsed.Address != value || !parsed.Address.Contains('@')) throw Invalid("请输入有效的邮箱地址，不支持显示名称或地址列表。");
        return value;
    }

    public static string[] NormalizeRecipients(string[]? recipients)
    {
        if (recipients is null || recipients.Length > 20) throw Invalid("每次最多配置 20 位收件人。");
        return recipients.Select(NormalizeAddress).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
    }

    private static NotificationException Invalid(string message) => new("VALIDATION_ERROR", message);
}
