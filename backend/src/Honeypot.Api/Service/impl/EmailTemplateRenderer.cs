using System.Globalization;
using System.Net;
using System.Text;
using Honeypot.Api.Common;
using Honeypot.Api.Models;
using Honeypot.Shared.Models;

namespace Honeypot.Api.Service.impl;

/// <summary>模板只装配受控 HTML；所有报告文本都编码，禁止把认证证据正文作为模板输入。</summary>
public sealed class EmailTemplateRenderer(IHostEnvironment environment) : IEmailTemplateRenderer
{
    public RenderedEmail RenderTest(DateTimeOffset now) => new("[通研 Honeypot] 邮件配置测试",
        Layout("邮件配置测试", "NOTIFICATION TEST", "验证邮件投递与模板显示", now, Read("Test.html")),
        "通研 Honeypot 邮件配置测试\n如果你已收到此邮件，说明本次测试邮件到达此邮箱。\nSMTP 已受理不保证最终进入收件箱。\n" + Local(now), "1");

    public RenderedEmail RenderReport(string kind, OperationReport report)
    {
        var title = NotificationMailService.ReportTitle(kind);
        var period = Local(report.Period.StartAtUtc) + " — " + Local(report.Period.EndAtUtc) + "（结束时间不包含在内）";
        var text = new StringBuilder().AppendLine(title).AppendLine(period);
        var template = Read(kind switch { "Weekly" => "Weekly.html", "Monthly" => "Monthly.html", _ => "Daily.html" });
        var coverage = report.Coverage.Status switch { "complete" => "采集覆盖完整", "partial" => "部分时段未覆盖", _ => "缺少采集覆盖数据" };
        var coveragePercent = report.Coverage.Status == "partial" && report.Coverage.CoveragePercent >= 99.95
            ? ">99.9%" : report.Coverage.CoveragePercent.ToString("0.0", CultureInfo.InvariantCulture) + "%";
        var coverageText = $"{coverage} · 覆盖率 {coveragePercent} · 未覆盖 {Duration(report.Coverage.UnknownSeconds)}";
        text.AppendLine(coverageText);
        var coverageHtml = $"<div style=\"padding:14px 16px;margin-bottom:20px;border-radius:8px;background:#fff7e8;color:#815414;font-size:13px;line-height:1.8;\">{Encode(coverageText)}<br>缺失时段不代表零事件；本报告只统计已经记录的观测。</div>";
        var metrics = new (string Label, string Value)[]
        {
            ("连接次数", Number(report.Totals.AcceptedConnections)), ("独立来源 IP", Number(report.Totals.UniqueSourceIps)),
            ("认证失败", Number(report.Totals.AuthenticationFailures)), ("协议异常", Number(report.Totals.ProtocolViolations)),
            ("原始事件步骤", Number(report.Totals.EventCount)), ("新观察来源 IP", Number(report.Totals.NewSourceIps)),
            ("认证证据数量", Number(report.Totals.EvidenceCount)), ("采集截断", Number(report.Totals.TruncatedEvents))
        };
        var metricsHtml = new StringBuilder("<table role=\"presentation\" style=\"width:100%;border-collapse:separate;border-spacing:6px;\">");
        for (var i = 0; i < metrics.Length; i++)
        {
            if (i % 2 == 0) metricsHtml.Append("<tr>");
            metricsHtml.Append($"<td style=\"width:50%;padding:16px;background:#f3f7fc;border:1px solid #e3ebf6;border-radius:8px;\"><p style=\"margin:0;color:#66758d;font-size:12px;\">{Encode(metrics[i].Label)}</p><p style=\"margin:9px 0 0;font-size:25px;font-weight:700;color:#183e70;\">{Encode(metrics[i].Value)}</p></td>");
            if (i % 2 == 1) metricsHtml.Append("</tr>");
            text.AppendLine(metrics[i].Label + ": " + metrics[i].Value);
        }
        metricsHtml.Append("</table>");
        var comparison = $"上一对应周期比较：连接 {Change(report.Comparison.ConnectionChangePercent)}，来源 IP {Change(report.Comparison.SourceIpChangePercent)}，认证失败 {Change(report.Comparison.AuthenticationFailureChangePercent)}。";
        metricsHtml.Append("<p style=\"margin:14px 6px;color:#6a7890;font-size:12px;line-height:1.9;\">" + Encode(comparison) + "</p>");
        text.AppendLine(comparison);
        var trend = Trend(report, text);
        var breakdowns = Breakdown("协议分布", report.Protocols, text) + Breakdown("目标端口", report.Ports, text) + Breakdown("来源 IP", report.Sources, text)
            + Breakdown("来源归属地", report.Regions, text) + Breakdown("认证用户名", report.Usernames, text, BreakdownKind.Authentication)
            + Breakdown("认证方式", report.AuthenticationMethods, text, BreakdownKind.Authentication)
            + Breakdown("风险信号", report.RiskSignals, text, BreakdownKind.Risk)
            + Breakdown("认证证据分类", report.Evidence, text, BreakdownKind.Evidence);
        var runtime = new (string Label, string Value)[]
        {
            ("采样次数", report.Runtime.SampleCount.ToString("N0", CultureInfo.InvariantCulture)),
            ("进程平均 / 峰值 CPU", Percent(report.Runtime.AverageProcessCpuPercent) + " / " + Percent(report.Runtime.PeakProcessCpuPercent)),
            ("进程平均 / 峰值内存", Memory(report.Runtime.AverageProcessMemoryBytes) + " / " + Memory(report.Runtime.PeakProcessMemoryBytes)),
            ("峰值活动连接", Number(report.Runtime.PeakActiveConnections)),
            ("监听器采样正常比例", Percent(report.Runtime.AllListenersRunningPercent)),
            ("峰值故障监听器", Number(report.Runtime.PeakFailedListeners)),
            ("数据盘最低可用空间", Memory(report.Runtime.MinimumDataDiskFreeBytes))
        };
        var runtimeHtml = Heading("运行健康") + SimpleTable(runtime);
        foreach (var row in runtime) text.AppendLine(row.Label + ": " + row.Value);
        runtimeHtml += "<p style=\"font-size:12px;color:#7b8798;line-height:1.8;\">资源指标表示蜜罐进程；CPU 占整机逻辑处理器总算力，内存为进程工作集。</p>";
        var mailHtml = "";
        if (report.MailSummary is { } mail)
        {
            var mailRows = new (string Label, string Value)[]
            {
                ("SMTP 已受理", Number(mail.Accepted)), ("投递失败", Number(mail.Failed)),
                ("待发送 / 重试中", Number(mail.Pending) + " / " + Number(mail.Retrying)),
                ("发送中 / 结果不确定", Number(mail.Sending) + " / " + Number(mail.Unknown))
            };
            mailHtml = Heading("邮件通知") + SimpleTable(mailRows);
            foreach (var row in mailRows) text.AppendLine(row.Label + ": " + row.Value);
        }
        var notes = report.Notes.Take(8).ToArray();
        var noteHtml = notes.Length == 0 ? "" : Heading("统计说明") + "<ul style=\"padding-left:20px;color:#6b7890;font-size:12px;line-height:1.9;\">" + string.Join("", notes.Select(note => "<li>" + Encode(note) + "</li>")) + "</ul>";
        foreach (var note in notes) text.AppendLine(note);
        var content = template.Replace("{{COVERAGE}}", coverageHtml, StringComparison.Ordinal)
            .Replace("{{METRICS}}", metricsHtml.ToString(), StringComparison.Ordinal).Replace("{{TREND}}", trend, StringComparison.Ordinal)
            .Replace("{{BREAKDOWNS}}", breakdowns, StringComparison.Ordinal).Replace("{{RUNTIME}}", runtimeHtml, StringComparison.Ordinal)
            .Replace("{{MAIL}}", mailHtml, StringComparison.Ordinal).Replace("{{NOTES}}", noteHtml, StringComparison.Ordinal);
        return new($"[通研 Honeypot] {title} · {TimeZoneInfo.ConvertTime(report.Period.StartAtUtc, NotificationScheduleCalculator.TimeZone):yyyy-MM-dd}",
            Layout(title, kind.ToUpperInvariant() + " REPORT", period, report.GeneratedAtUtc, content), text.ToString(), "2");
    }

    private string Layout(string title, string badge, string period, DateTimeOffset generated, string content) => Read("Layout.html")
        .Replace("{{TITLE}}", Encode(title), StringComparison.Ordinal).Replace("{{PREHEADER}}", Encode(title + " · " + period), StringComparison.Ordinal)
        .Replace("{{BADGE}}", Encode(badge), StringComparison.Ordinal).Replace("{{PERIOD}}", Encode(period), StringComparison.Ordinal)
        .Replace("{{GENERATED}}", Encode(Local(generated)), StringComparison.Ordinal).Replace("{{CONTENT}}", content, StringComparison.Ordinal);

    private string Read(string name)
    {
        var path = Path.Combine(environment.ContentRootPath, "Resources", "EmailTemplates", name);
        if (!File.Exists(path)) path = Path.Combine(AppContext.BaseDirectory, "Resources", "EmailTemplates", name);
        return File.ReadAllText(path);
    }

    private static string Trend(OperationReport report, StringBuilder text)
    {
        // 邮件使用表格条形图，无脚本、外部字体或远程图片依赖。
        var points = report.Trend;
        if (points.Count == 0) return Heading("连接趋势") + Empty();
        var groups = points.Select((point, index) => (point, index)).GroupBy(item => item.index / Math.Max(1, (int)Math.Ceiling(points.Count / 12d)))
            .Select(group => new { Time = group.First().point.StartAtUtc,
                Connections = group.Any(item => item.point.Connections.HasValue) ? group.Sum(item => item.point.Connections) : null,
                Partial = group.Any(item => item.point.CoverageStatus != "complete") }).ToArray();
        var max = Math.Max(1, groups.Max(item => item.Connections) ?? 0);
        var html = new StringBuilder(Heading("连接趋势") + "<table role=\"presentation\" style=\"width:100%;border-collapse:collapse;\">");
        text.AppendLine("连接趋势（分组合计）：");
        foreach (var point in groups)
        {
            var width = Math.Max(1, (point.Connections ?? 0) * 100d / max).ToString("0.0", CultureInfo.InvariantCulture);
            var label = TimeZoneInfo.ConvertTime(point.Time, NotificationScheduleCalculator.TimeZone).ToString("MM-dd HH:mm", CultureInfo.InvariantCulture);
            var color = point.Partial ? "#d9a445" : "#4d8be8";
            var bar = point.Connections is > 0 ? $"<table role=\"presentation\" style=\"width:{width}%;border-collapse:collapse;\"><tr><td style=\"background:{color};height:9px;border-radius:3px;font-size:1px;\">&nbsp;</td></tr></table>" : "";
            var display = point.Connections.HasValue ? Number(point.Connections) + (point.Partial ? "（部分）" : "") : "未采集";
            html.Append($"<tr><td style=\"padding:6px 8px 6px 0;font-size:11px;color:#708098;width:90px;\">{Encode(label)}</td><td style=\"padding:6px 0;\">{bar}</td><td style=\"padding-left:10px;text-align:right;font-size:12px;color:#45546a;width:90px;\">{Encode(display)}</td></tr>");
            text.AppendLine(label + ": " + display);
        }
        return html.Append("</table>").ToString();
    }

    private enum BreakdownKind { Connections, Authentication, Risk, Evidence }

    private static string Breakdown(string title, IReadOnlyList<ReportBreakdown> rows, StringBuilder text, BreakdownKind kind = BreakdownKind.Connections)
    {
        var html = new StringBuilder(Heading(title));
        text.AppendLine(title + "（前 5）：");
        if (rows.Count == 0) return html.Append(Empty()).ToString();
        (string Label, Func<ReportBreakdown, long> Read)[] columns = kind switch
        {
            BreakdownKind.Authentication => [("认证尝试", row => row.Events), ("认证失败", row => row.AuthenticationFailures), ("来源 IP", row => row.SourceIps)],
            BreakdownKind.Risk => [("事件数", row => row.Events), ("来源 IP", row => row.SourceIps)],
            // 当前证据分类来自带 credentialArtifactId 的事件，不把关联事件数说成去重证据数。
            BreakdownKind.Evidence => [("关联事件数", row => row.Events), ("来源 IP", row => row.SourceIps)],
            _ => [("连接", row => row.Connections), ("认证失败", row => row.AuthenticationFailures), ("来源 IP", row => row.SourceIps)]
        };
        html.Append("<table style=\"width:100%;border-collapse:collapse;font-size:12px;\"><tr style=\"background:#f3f6fa;color:#6e7d92;\"><th style=\"padding:10px;text-align:left;\">项目</th>");
        foreach (var column in columns) html.Append($"<th style=\"padding:10px;text-align:right;\">{Encode(column.Label)}</th>");
        html.Append("</tr>");
        foreach (var row in rows.Take(5))
        {
            html.Append($"<tr><td style=\"padding:11px 10px;border-bottom:1px solid #edf1f5;word-break:break-all;\">{Encode(row.Key)}</td>");
            foreach (var column in columns) html.Append($"<td style=\"padding:11px 10px;border-bottom:1px solid #edf1f5;text-align:right;\">{Number(column.Read(row))}</td>");
            html.Append("</tr>");
            text.AppendLine(Plain(row.Key) + ": " + string.Join(" / ", columns.Select(column => column.Label + " " + Number(column.Read(row)))));
        }
        return html.Append("</table>").ToString();
    }

    private static string SimpleTable(IEnumerable<(string Label, string Value)> rows) => "<table style=\"width:100%;border-collapse:collapse;font-size:13px;\">" + string.Join("", rows.Select(row =>
        $"<tr><td style=\"padding:11px 8px;border-bottom:1px solid #edf1f5;color:#6a7890;\">{Encode(row.Label)}</td><td style=\"padding:11px 8px;border-bottom:1px solid #edf1f5;text-align:right;font-weight:600;color:#2d435f;\">{Encode(row.Value)}</td></tr>")) + "</table>";
    private static string Heading(string title) => "<h2 style=\"margin:28px 0 14px;font-size:17px;color:#223b5c;\">" + Encode(title) + "</h2>";
    private static string Empty() => "<p style=\"font-size:13px;color:#8793a5;\">当前区间暂无已记录数据。</p>";
    private static string Encode(string? value) => WebUtility.HtmlEncode(Plain(value))
        .Replace("{", "&#123;", StringComparison.Ordinal).Replace("}", "&#125;", StringComparison.Ordinal);
    private static string Plain(string? value)
    {
        var text = new string((value ?? string.Empty).Where(character => !char.IsControl(character)).Take(300).ToArray());
        return text;
    }
    private static string Number(long? value) => value?.ToString("N0", CultureInfo.InvariantCulture) ?? "无观测";
    private static string Percent(double? value) => value.HasValue ? value.Value.ToString("0.0", CultureInfo.InvariantCulture) + "%" : "无观测";
    private static string Change(double? value) => value.HasValue ? value.Value.ToString("+0.0;-0.0;0.0", CultureInfo.InvariantCulture) + "%" : "不可比较";
    private static string Memory(long? value)
    {
        if (!value.HasValue) return "无观测";
        var gibibytes = value.Value / 1024d / 1024d / 1024d;
        return gibibytes >= 1 ? gibibytes.ToString("0.0", CultureInfo.InvariantCulture) + " GiB"
            : (value.Value / 1024d / 1024d).ToString("0.0", CultureInfo.InvariantCulture) + " MiB";
    }
    private static string Duration(double seconds) => seconds switch
    {
        <= 0 => "0 分钟",
        < 60 => "少于1分钟",
        < 3600 => (seconds / 60).ToString("0.0", CultureInfo.InvariantCulture) + " 分钟",
        _ => (seconds / 3600).ToString("0.0", CultureInfo.InvariantCulture) + " 小时"
    };
    private static string Local(DateTimeOffset value) => TimeZoneInfo.ConvertTime(value, NotificationScheduleCalculator.TimeZone).ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture);
}
