using System.Globalization;
using Honeypot.Api.Models;

namespace Honeypot.Api.Common;

/// <summary>仅按北京时间自然周期调度，停机后选择最近一个已到发送点，不遍历历史补发。</summary>
public static class NotificationScheduleCalculator
{
    public static TimeZoneInfo TimeZone { get; } = TimeZoneInfo.FindSystemTimeZoneById("Asia/Shanghai");

    public static DueReportPeriod MostRecent(string kind, string sendTime, DateTimeOffset now)
    {
        var local = TimeZoneInfo.ConvertTime(now, TimeZone).DateTime;
        var time = TimeOnly.ParseExact(sendTime, "HH:mm", CultureInfo.InvariantCulture);
        var boundary = kind switch
        {
            "Daily" => local.Date,
            "Weekly" => local.Date.AddDays(-((7 + (int)local.DayOfWeek - (int)DayOfWeek.Monday) % 7)),
            "Monthly" => new DateTime(local.Year, local.Month, 1),
            _ => throw new ArgumentException("不支持的报告周期。", nameof(kind))
        };
        var scheduled = boundary.Add(time.ToTimeSpan());
        if (scheduled > local)
        {
            boundary = Previous(kind, boundary);
            scheduled = boundary.Add(time.ToTimeSpan());
        }
        return new(ToUtc(scheduled), ToUtc(Previous(kind, boundary)), ToUtc(boundary));
    }

    public static DateTimeOffset Next(string kind, string sendTime, DateTimeOffset now)
    {
        var latest = MostRecent(kind, sendTime, now);
        var local = TimeZoneInfo.ConvertTime(latest.ScheduledAtUtc, TimeZone).DateTime;
        return ToUtc(kind switch { "Daily" => local.AddDays(1), "Weekly" => local.AddDays(7), "Monthly" => local.AddMonths(1), _ => throw new ArgumentException("周期无效。") });
    }

    private static DateTime Previous(string kind, DateTime time) => kind switch
    {
        "Daily" => time.AddDays(-1), "Weekly" => time.AddDays(-7), "Monthly" => time.AddMonths(-1), _ => throw new ArgumentException("周期无效。")
    };
    private static DateTimeOffset ToUtc(DateTime local) => new(TimeZoneInfo.ConvertTimeToUtc(DateTime.SpecifyKind(local, DateTimeKind.Unspecified), TimeZone));
}
