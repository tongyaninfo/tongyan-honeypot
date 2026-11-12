using System.Text.Json;
using Honeypot.Api.Common;
using Honeypot.Api.Data;
using Honeypot.Api.Data.Models;
using Honeypot.Api.Models;
using Honeypot.Shared.Models;
using Microsoft.EntityFrameworkCore;

namespace Honeypot.Api.Service.impl;

/// <summary>单机持久发件箱。邮件提交不参加业务事务，受理不确定时停止自动重试。</summary>
public sealed class NotificationMailService(
    IDbContextFactory<HoneypotDbContext> database,
    INotificationSettingsStore settingsStore,
    IReportService reports,
    IEmailTemplateRenderer renderer,
    IMailTransport transport,
    IResourceIdGenerator ids,
    TimeProvider time,
    ISyslogPublisher? logs = null) : INotificationMailService
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly SemaphoreSlim _queueGate = new(1, 1);
    private readonly SemaphoreSlim _sendGate = new(1, 1);
    private readonly SemaphoreSlim _scheduleGate = new(1, 1);

    public async Task<NotificationTaskResult> QueueTestAsync(TestEmailRequest request, string requestedBy, CancellationToken cancellationToken = default)
    {
        var recipient = NotificationSettingsValidation.NormalizeAddress(request.Recipient);
        var settings = await settingsStore.GetAsync(cancellationToken);
        _ = NotificationSettingsValidation.Normalize(settings with { Enabled = true }, settings.HasCredential);
        // 测试允许通知总开关关闭，但只使用已保存并能解密的配置。
        _ = await settingsStore.GetTransportAsync(cancellationToken);
        await _queueGate.WaitAsync(cancellationToken);
        try
        {
            await using var db = await database.CreateDbContextAsync(cancellationToken);
            var now = time.GetUtcNow();
            var threshold = now.AddSeconds(-settings.TestCooldownSeconds).ToUnixTimeMilliseconds();
            if (await db.Set<EmailDeliveryEntity>().AnyAsync(item => item.Kind == "Test" && item.CreatedUnixMs > threshold, cancellationToken))
                throw RateLimited("测试邮件仍在冷却时间内，请稍后重试。");
            await EnsureQueueCapacityAsync(db, 1, cancellationToken);
            var rendered = renderer.RenderTest(now);
            var delivery = CreateDelivery("Test", recipient, rendered, null, "test:" + ids.NewId(), requestedBy, now);
            db.Add(delivery);
            await db.SaveChangesAsync(cancellationToken);
            MailLog(delivery, "MAIL_TEST_QUEUED", SyslogSeverity.Informational);
            return new([delivery.Id], "测试邮件已排队，请在邮件记录中查看 SMTP 受理结果。");
        }
        finally { _queueGate.Release(); }
    }

    public Task<NotificationTaskResult> QueueReportAsync(ReportSendRequest request, string requestedBy, CancellationToken cancellationToken = default) =>
        QueueReportCoreAsync(request, requestedBy, null, cancellationToken);

    public Task<NotificationTaskResult> QueueDefaultReportAsync(ReportQuery query, string mcpKeyId, Guid requestId,
        CancellationToken cancellationToken = default)
    {
        // MCP 工具的业务入口不允许指定收件人；请求标识只在同一 Key 内生效。
        var requester = $"mcp:{mcpKeyId}";
        return QueueReportCoreAsync(new() { Period = query.Period, StartAtUtc = query.StartAtUtc, EndAtUtc = query.EndAtUtc },
            requester, $"{requester}:{requestId:N}", cancellationToken);
    }

    private async Task<NotificationTaskResult> QueueReportCoreAsync(ReportSendRequest request, string requestedBy,
        string? stableTaskKey, CancellationToken cancellationToken)
    {
        await _queueGate.WaitAsync(cancellationToken);
        try
        {
            await using var db = await database.CreateDbContextAsync(cancellationToken);
            var kind = request.Period switch { "day" => "Daily", "week" => "Weekly", "month" => "Monthly", "custom" => "Custom", _ => throw new NotificationException("VALIDATION_ERROR", "报告周期无效。") };
            if (stableTaskKey is not null && await db.Set<ReportSnapshotEntity>().AsNoTracking()
                    .SingleOrDefaultAsync(row => row.TaskKey == stableTaskKey, cancellationToken) is { } existing)
            {
                if (existing.PeriodKind != kind || (kind == "Custom" &&
                    (existing.PeriodStartUnixMs != request.StartAtUtc?.ToUnixTimeMilliseconds() ||
                     existing.PeriodEndUnixMs != request.EndAtUtc?.ToUnixTimeMilliseconds())))
                    throw new NotificationException("CONFLICT", "此请求标识已用于其他报告参数。");
                var deliveryIds = await db.Set<EmailDeliveryEntity>().AsNoTracking()
                    .Where(row => row.ReportSnapshotId == existing.Id).OrderBy(row => row.Id).Select(row => row.Id)
                    .ToArrayAsync(cancellationToken);
                return new(deliveryIds, "此请求已入队，返回原报告任务编号。");
            }

            var settings = await settingsStore.GetAsync(cancellationToken);
            EnsureEnabled(settings);
            var recipients = ResolveRecipients(request.Recipients, settings.DefaultRecipients);
            var threshold = time.GetUtcNow().AddSeconds(-settings.ResendCooldownSeconds).ToUnixTimeMilliseconds();
            if (await db.Set<EmailDeliveryEntity>().AnyAsync(item => item.RequestedBy == requestedBy && item.Kind != "Test" && item.CreatedUnixMs > threshold, cancellationToken))
                throw RateLimited("报告邮件仍在冷却时间内，请稍后重试。");
            await EnsureQueueCapacityAsync(db, recipients.Length, cancellationToken);
            var report = await reports.GenerateAsync(new ReportQuery { Period = request.Period, StartAtUtc = request.StartAtUtc, EndAtUtc = request.EndAtUtc }, cancellationToken);
            var queued = await PersistReportAsync(db, kind, report, recipients, stableTaskKey ?? "manual:" + ids.NewId(), requestedBy, cancellationToken);
            return stableTaskKey is null ? queued : queued with { DeliveryIds = queued.DeliveryIds.Order(StringComparer.Ordinal).ToArray() };
        }
        finally { _queueGate.Release(); }
    }

    public async Task<NotificationTaskResult> RetryAsync(string id, string requestedBy, CancellationToken cancellationToken = default)
    {
        var settings = await settingsStore.GetAsync(cancellationToken);
        await _queueGate.WaitAsync(cancellationToken);
        try
        {
            await using var db = await database.CreateDbContextAsync(cancellationToken);
            var item = await db.Set<EmailDeliveryEntity>().FindAsync([id], cancellationToken)
                ?? throw new NotificationException("NOT_FOUND", "邮件记录不存在。");
            if (item.Kind != "Test") EnsureEnabled(settings);
            if (item.Status is not ("Failed" or "Unknown")) throw new NotificationException("RETRY_NOT_ALLOWED", "只有失败或结果不确定的邮件可以手动重试。");
            var now = time.GetUtcNow();
            if (now.ToUnixTimeMilliseconds() - item.UpdatedUnixMs < settings.ResendCooldownSeconds * 1000L)
                throw RateLimited("该邮件仍在重试冷却时间内。");
            item.Status = "Pending";
            item.AutomaticAttemptCount = 0;
            item.NextAttemptUnixMs = now.ToUnixTimeMilliseconds();
            item.UpdatedUnixMs = now.ToUnixTimeMilliseconds();
            item.RequestedBy = requestedBy;
            item.LastErrorCode = null;
            item.LastErrorMessage = null;
            await db.SaveChangesAsync(cancellationToken);
            MailLog(item, "MAIL_RETRY_REQUESTED", SyslogSeverity.Notice);
            return new([item.Id], "邮件已重新排队；结果不确定的邮件可能产生重复投递。");
        }
        finally { _queueGate.Release(); }
    }

    public async Task<NotificationPage<EmailDeliverySummary>> GetDeliveriesAsync(EmailDeliveryQuery query, CancellationToken cancellationToken = default)
    {
        ValidatePage(query.Page, query.PageSize);
        await using var db = await database.CreateDbContextAsync(cancellationToken);
        var rows = db.Set<EmailDeliveryEntity>().AsNoTracking();
        if (query.ReportsOnly) rows = rows.Where(item => item.ReportSnapshotId != null);
        if (!string.IsNullOrWhiteSpace(query.Kind)) rows = rows.Where(item => item.Kind == query.Kind);
        if (!string.IsNullOrWhiteSpace(query.Status)) rows = rows.Where(item => item.Status == query.Status);
        if (!string.IsNullOrWhiteSpace(query.Recipient)) rows = rows.Where(item => item.Recipient.Contains(query.Recipient));
        if (query.FromUtc is { } from) { var value = from.ToUnixTimeMilliseconds(); rows = rows.Where(item => item.CreatedUnixMs >= value); }
        if (query.ToUtc is { } to) { var value = to.ToUnixTimeMilliseconds(); rows = rows.Where(item => item.CreatedUnixMs < value); }
        var total = await rows.CountAsync(cancellationToken);
        var items = await rows.OrderByDescending(item => item.CreatedUnixMs).ThenByDescending(item => item.Id)
            .Skip((query.Page - 1) * query.PageSize).Take(query.PageSize).ToArrayAsync(cancellationToken);
        var reportIds = items.Select(item => item.ReportSnapshotId).Where(value => value is not null).ToArray();
        var snapshots = await db.Set<ReportSnapshotEntity>().AsNoTracking().Where(item => reportIds.Contains(item.Id)).ToDictionaryAsync(item => item.Id, cancellationToken);
        return new(items.Select(item => Summary(item, item.ReportSnapshotId is not null ? snapshots.GetValueOrDefault(item.ReportSnapshotId) : null)).ToArray(), total, query.Page, query.PageSize);
    }

    public async Task<EmailDeliveryDetails?> GetDeliveryAsync(string id, CancellationToken cancellationToken = default)
    {
        await using var db = await database.CreateDbContextAsync(cancellationToken);
        var item = await db.Set<EmailDeliveryEntity>().AsNoTracking().SingleOrDefaultAsync(row => row.Id == id, cancellationToken);
        if (item is null) return null;
        var snapshot = item.ReportSnapshotId is null ? null : await db.Set<ReportSnapshotEntity>().AsNoTracking().SingleOrDefaultAsync(row => row.Id == item.ReportSnapshotId, cancellationToken);
        var attempts = await db.Set<EmailDeliveryAttemptEntity>().AsNoTracking().Where(row => row.DeliveryId == id).OrderBy(row => row.Number).ToArrayAsync(cancellationToken);
        return new(Summary(item, snapshot), item.HtmlBody, item.TextBody, snapshot?.TemplateVersion ?? "1",
            attempts.Select(row => new EmailDeliveryAttempt(row.Number, Utc(row.StartedUnixMs), NullableUtc(row.CompletedUnixMs), row.Status, row.ErrorCode, row.ErrorMessage)).ToArray(),
            item.Status is "Failed" or "Unknown");
    }

    public async Task<NotificationPage<ReportHistoryItem>> GetReportsAsync(int page, int pageSize, string? kind, CancellationToken cancellationToken = default)
    {
        ValidatePage(page, pageSize);
        await using var db = await database.CreateDbContextAsync(cancellationToken);
        var query = db.Set<ReportSnapshotEntity>().AsNoTracking();
        if (!string.IsNullOrWhiteSpace(kind)) query = query.Where(row => row.PeriodKind == kind);
        var total = await query.CountAsync(cancellationToken);
        var snapshots = await query.OrderByDescending(row => row.CreatedUnixMs).ThenByDescending(row => row.Id).Skip((page - 1) * pageSize).Take(pageSize).ToArrayAsync(cancellationToken);
        var snapshotIds = snapshots.Select(row => row.Id).ToArray();
        var counts = await db.Set<EmailDeliveryEntity>().Where(row => row.ReportSnapshotId != null && snapshotIds.Contains(row.ReportSnapshotId))
            .GroupBy(row => row.ReportSnapshotId!).Select(group => new { Id = group.Key, Count = group.Count() }).ToDictionaryAsync(row => row.Id, row => row.Count, cancellationToken);
        return new(snapshots.Select(row => new ReportHistoryItem(row.Id, row.PeriodKind, ReportTitle(row.PeriodKind), Utc(row.PeriodStartUnixMs), Utc(row.PeriodEndUnixMs), Utc(row.CreatedUnixMs), counts.GetValueOrDefault(row.Id))).ToArray(), total, page, pageSize);
    }

    public async Task<OperationReport?> GetReportAsync(string id, CancellationToken cancellationToken = default)
    {
        await using var db = await database.CreateDbContextAsync(cancellationToken);
        var snapshot = await db.Set<ReportSnapshotEntity>().AsNoTracking().SingleOrDefaultAsync(row => row.Id == id, cancellationToken);
        return snapshot is null ? null : JsonSerializer.Deserialize<OperationReport>(snapshot.ReportJson, JsonOptions);
    }

    public async Task ScheduleDueReportsAsync(CancellationToken cancellationToken = default)
    {
        if (!await _scheduleGate.WaitAsync(0, cancellationToken)) return;
        try
        {
            var schedules = await settingsStore.GetScheduleStatesAsync(cancellationToken);
            foreach (var state in schedules)
            {
                var period = NotificationScheduleCalculator.MostRecent(state.Settings.Kind, state.Settings.SendTime, time.GetUtcNow());
                if (period.ScheduledAtUtc < state.ActivatedAtUtc || state.Settings.LastRunAtUtc >= period.ScheduledAtUtc) continue;
                var key = $"automatic:{state.Settings.Kind}:{period.StartAtUtc.ToUnixTimeSeconds()}:{period.EndAtUtc.ToUnixTimeSeconds()}";
                await _queueGate.WaitAsync(cancellationToken);
                try
                {
                    await using var db = await database.CreateDbContextAsync(cancellationToken);
                    if (await db.Set<ReportSnapshotEntity>().AnyAsync(row => row.TaskKey == key, cancellationToken))
                    {
                        await settingsStore.RecordScheduleRunAsync(state.Settings.Kind, period.ScheduledAtUtc, "Queued", cancellationToken);
                        continue;
                    }
                    var settings = await settingsStore.GetAsync(cancellationToken);
                    if (!settings.Enabled) continue;
                    var current = settings.Schedules.Single(item => item.Kind == state.Settings.Kind);
                    if (!current.Enabled || current.SendTime != state.Settings.SendTime) continue;
                    var recipients = ResolveRecipients(current.Recipients, settings.DefaultRecipients);
                    await EnsureQueueCapacityAsync(db, recipients.Length, cancellationToken);
                    var report = await reports.GenerateAsync(new ReportQuery { Period = "custom", StartAtUtc = period.StartAtUtc, EndAtUtc = period.EndAtUtc }, cancellationToken);
                    await PersistReportAsync(db, state.Settings.Kind, report, recipients, key, "scheduler", cancellationToken);
                    await settingsStore.RecordScheduleRunAsync(state.Settings.Kind, period.ScheduledAtUtc, "Queued", cancellationToken);
                }
                catch (Exception error) when (error is not OperationCanceledException)
                {
                    // 失败仅更新状态，不前移上次成功调度点；下轮可以继续补偿。
                    logs?.Publish("honeypot-report", "REPORT_SCHEDULE_FAILED", SyslogSeverity.Error,
                        new Dictionary<string, object?> { ["kind"] = state.Settings.Kind, ["exceptionType"] = error.GetType().Name });
                    try { await settingsStore.RecordScheduleRunAsync(state.Settings.Kind, null, "Failed", cancellationToken); }
                    catch (NotificationException) { /* 配置存储也故障时保留原状态，继续处理其他计划。 */ }
                }
                finally { _queueGate.Release(); }
            }
        }
        finally { _scheduleGate.Release(); }
    }

    public async Task ProcessPendingAsync(CancellationToken cancellationToken = default)
    {
        if (!await _sendGate.WaitAsync(0, cancellationToken)) return;
        try
        {
            await using var db = await database.CreateDbContextAsync(cancellationToken);
            var now = time.GetUtcNow();
            var nowMs = now.ToUnixTimeMilliseconds();
            await RecoverExpiredAsync(db, nowMs, cancellationToken);
            var settings = await settingsStore.GetAsync(cancellationToken);
            var item = await db.Set<EmailDeliveryEntity>().Where(row => (row.Status == "Pending" || row.Status == "Retrying") &&
                (row.NextAttemptUnixMs == null || row.NextAttemptUnixMs <= nowMs) && (settings.Enabled || row.Kind == "Test"))
                .OrderBy(row => row.CreatedUnixMs).FirstOrDefaultAsync(cancellationToken);
            if (item is null) return;
            var since = now.AddHours(-1).ToUnixTimeMilliseconds();
            var global = await db.Set<EmailDeliveryAttemptEntity>().CountAsync(row => row.StartedUnixMs > since, cancellationToken);
            var recipientCount = await (from attempt in db.Set<EmailDeliveryAttemptEntity>()
                join delivery in db.Set<EmailDeliveryEntity>() on attempt.DeliveryId equals delivery.Id
                where attempt.StartedUnixMs > since && delivery.RecipientKey == item.RecipientKey
                select attempt.Id).CountAsync(cancellationToken);
            if (global >= settings.MaxPerHour || recipientCount >= settings.MaxPerRecipientPerHour)
            {
                item.NextAttemptUnixMs = now.AddMinutes(1).ToUnixTimeMilliseconds();
                item.UpdatedUnixMs = nowMs;
                item.LastErrorCode = "RATE_LIMITED";
                item.LastErrorMessage = "已达到小时发送配额，任务保留并延后发送。";
                await db.SaveChangesAsync(cancellationToken);
                return;
            }
            // 租约比最大 SMTP 超时长；只有过期 Sending 才恢复为 Unknown，避免误伤正在执行的任务。
            var leaseUntil = now.AddMinutes(5).ToUnixTimeMilliseconds();
            var expectedAttempt = item.AttemptCount;
            var automaticAttempt = item.AutomaticAttemptCount + 1;
            EmailDeliveryAttemptEntity attemptRow;
            await using (var transaction = await db.Database.BeginTransactionAsync(cancellationToken))
            {
                var claimed = await db.Set<EmailDeliveryEntity>().Where(row => row.Id == item.Id &&
                    (row.Status == "Pending" || row.Status == "Retrying") && row.AttemptCount == expectedAttempt)
                    .ExecuteUpdateAsync(update => update.SetProperty(row => row.Status, "Sending")
                        .SetProperty(row => row.LeaseExpiresUnixMs, leaseUntil).SetProperty(row => row.UpdatedUnixMs, nowMs)
                        .SetProperty(row => row.AttemptCount, expectedAttempt + 1).SetProperty(row => row.AutomaticAttemptCount, automaticAttempt), cancellationToken);
                if (claimed == 0) return;
                // ExecuteUpdate 不刷新跟踪实体，必须重新读取，避免后续保存把尝试序号写回旧值。
                await db.Entry(item).ReloadAsync(cancellationToken);
                attemptRow = new EmailDeliveryAttemptEntity { Id = ids.NewId(), DeliveryId = item.Id, Number = item.AttemptCount, StartedUnixMs = nowMs };
                db.Add(attemptRow);
                await db.SaveChangesAsync(cancellationToken);
                await transaction.CommitAsync(cancellationToken);
            }
            MailTransportResult result;
            try
            {
                var configuration = await settingsStore.GetTransportAsync(cancellationToken);
                result = await transport.SendAsync(configuration, new(item.Recipient, item.MessageId, item.Subject, item.HtmlBody, item.TextBody), cancellationToken);
            }
            catch (NotificationException error)
            { result = new("Failed", error.Code, error.Message); }
            catch (Exception error) when (error is OperationCanceledException or IOException)
            { result = new("Unknown", "SMTP_RESULT_UNKNOWN", "投递执行中断，请核实是否受理后再手动重试。"); }
            var completed = time.GetUtcNow();
            item.Status = result.Status;
            item.LastErrorCode = result.ErrorCode;
            item.LastErrorMessage = result.ErrorMessage;
            item.UpdatedUnixMs = completed.ToUnixTimeMilliseconds();
            item.LeaseExpiresUnixMs = null;
            item.NextAttemptUnixMs = null;
            if (result.Status == "Accepted") item.AcceptedUnixMs = completed.ToUnixTimeMilliseconds();
            if (result.Status == "Retrying")
            {
                if (item.AutomaticAttemptCount >= 3)
                {
                    item.Status = "Failed";
                    item.LastErrorCode = "SMTP_RETRIES_EXHAUSTED";
                    item.LastErrorMessage = "邮件已达到自动重试上限，请检查配置后手动重试。";
                }
                else item.NextAttemptUnixMs = completed.AddMinutes(item.AutomaticAttemptCount == 1 ? 1 : 5).ToUnixTimeMilliseconds();
            }
            attemptRow.Status = item.Status;
            attemptRow.CompletedUnixMs = completed.ToUnixTimeMilliseconds();
            attemptRow.ErrorCode = item.LastErrorCode;
            attemptRow.ErrorMessage = item.LastErrorMessage;
            // 即使宿主正在停止也尝试写回受理结果；写入失败保留租约，后续转为 Unknown。
            await db.SaveChangesAsync(CancellationToken.None);
            MailLog(item, "MAIL_DELIVERY_RESULT", item.Status switch
            {
                "Accepted" => SyslogSeverity.Informational,
                "Retrying" or "Unknown" => SyslogSeverity.Warning,
                _ => SyslogSeverity.Error,
            });
            if (item.ReportSnapshotId is not null) await UpdateScheduleStatusAsync(db, item.ReportSnapshotId, CancellationToken.None);
        }
        finally { _sendGate.Release(); }
    }

    private async Task<NotificationTaskResult> PersistReportAsync(HoneypotDbContext db, string kind, OperationReport report,
        string[] recipients, string taskKey, string requestedBy, CancellationToken cancellationToken)
    {
        var now = time.GetUtcNow();
        var rendered = renderer.RenderReport(kind, report);
        var snapshot = new ReportSnapshotEntity
        {
            Id = ids.NewId(), PeriodKind = kind, TaskKey = taskKey,
            PeriodStartUnixMs = report.Period.StartAtUtc.ToUnixTimeMilliseconds(), PeriodEndUnixMs = report.Period.EndAtUtc.ToUnixTimeMilliseconds(),
            CreatedUnixMs = now.ToUnixTimeMilliseconds(), ReportJson = JsonSerializer.Serialize(report, JsonOptions), TemplateVersion = rendered.TemplateVersion
        };
        db.Add(snapshot);
        var deliveries = recipients.Select(recipient => CreateDelivery(kind, recipient, rendered, snapshot.Id, taskKey, requestedBy, now)).ToArray();
        db.AddRange(deliveries);
        // 快照和每位收件人的发件任务在同一次数据库事务内提交。
        await db.SaveChangesAsync(cancellationToken);
        logs?.Publish("honeypot-report", "REPORT_SNAPSHOT_QUEUED", SyslogSeverity.Informational,
            new Dictionary<string, object?> { ["reportId"] = snapshot.Id, ["kind"] = kind, ["count"] = deliveries.Length });
        foreach (var delivery in deliveries) MailLog(delivery, "MAIL_QUEUED", SyslogSeverity.Informational);
        return new(deliveries.Select(item => item.Id).ToArray(), "报告邮件已排队，统计快照及正文已冻结。");
    }

    private EmailDeliveryEntity CreateDelivery(string kind, string recipient, RenderedEmail content, string? reportId,
        string taskKey, string requestedBy, DateTimeOffset now)
    {
        var id = ids.NewId();
        return new()
        {
            Id = id, Kind = kind, Recipient = recipient, RecipientKey = recipient.ToLowerInvariant(), Subject = content.Subject, HtmlBody = content.HtmlBody, TextBody = content.TextBody,
            ReportSnapshotId = reportId, DeduplicationKey = taskKey + ":" + recipient.ToLowerInvariant(), MessageId = id + "@honeypot.local",
            CreatedUnixMs = now.ToUnixTimeMilliseconds(), UpdatedUnixMs = now.ToUnixTimeMilliseconds(), NextAttemptUnixMs = now.ToUnixTimeMilliseconds(), RequestedBy = requestedBy
        };
    }

    private async Task RecoverExpiredAsync(HoneypotDbContext db, long now, CancellationToken cancellationToken)
    {
        var expired = await db.Set<EmailDeliveryEntity>().Where(row => row.Status == "Sending" && (row.LeaseExpiresUnixMs == null || row.LeaseExpiresUnixMs <= now)).ToArrayAsync(cancellationToken);
        if (expired.Length == 0) return;
        foreach (var row in expired)
        {
            row.Status = "Unknown";
            row.UpdatedUnixMs = now;
            row.LeaseExpiresUnixMs = null;
            row.LastErrorCode = "WORKER_INTERRUPTED";
            row.LastErrorMessage = "发送任务租约已过期，受理结果不确定，系统不会自动重发。";
        }
        var ids = expired.Select(row => row.Id).ToArray();
        var attempts = await db.Set<EmailDeliveryAttemptEntity>().Where(row => ids.Contains(row.DeliveryId) && row.Status == "Sending").ToArrayAsync(cancellationToken);
        foreach (var row in attempts)
        {
            row.Status = "Unknown";
            row.CompletedUnixMs = now;
            row.ErrorCode = "WORKER_INTERRUPTED";
            row.ErrorMessage = "发送进程中断或租约过期，受理结果不确定。";
        }
        await db.SaveChangesAsync(cancellationToken);
        foreach (var row in expired) MailLog(row, "MAIL_DELIVERY_RESULT", SyslogSeverity.Warning);
        foreach (var reportId in expired.Select(row => row.ReportSnapshotId).Where(value => value is not null).Distinct())
            await UpdateScheduleStatusAsync(db, reportId!, cancellationToken);
    }

    private async Task UpdateScheduleStatusAsync(HoneypotDbContext db, string reportId, CancellationToken cancellationToken)
    {
        await _queueGate.WaitAsync(cancellationToken);
        try
        {
            var snapshot = await db.Set<ReportSnapshotEntity>().AsNoTracking().SingleOrDefaultAsync(row => row.Id == reportId, cancellationToken);
            if (snapshot is null || !snapshot.TaskKey.StartsWith("automatic:", StringComparison.Ordinal)) return;
            var latestId = await db.Set<ReportSnapshotEntity>().AsNoTracking().Where(row => row.PeriodKind == snapshot.PeriodKind && row.TaskKey.StartsWith("automatic:"))
                .OrderByDescending(row => row.CreatedUnixMs).ThenByDescending(row => row.Id).Select(row => row.Id).FirstOrDefaultAsync(cancellationToken);
            if (latestId != reportId) return; // 旧周期晚到的结果不能覆盖新周期计划状态。
            var states = await db.Set<EmailDeliveryEntity>().Where(row => row.ReportSnapshotId == reportId).Select(row => row.Status).ToArrayAsync(cancellationToken);
            var status = states.Any(value => value is "Pending" or "Retrying" or "Sending") ? "Sending"
                : states.Any(value => value == "Unknown") ? "Unknown"
                : states.All(value => value == "Accepted") ? "Accepted"
                : states.Any(value => value == "Accepted") ? "PartiallyFailed" : "Failed";
            try { await settingsStore.RecordScheduleRunAsync(snapshot.PeriodKind, null, status, cancellationToken); }
            catch (NotificationException error)
            {
                // 投递结果已入库，配置状态写回失败不能触发重复投递。
                logs?.Publish("honeypot-report", "REPORT_STATUS_WRITE_FAILED", SyslogSeverity.Error,
                    new Dictionary<string, object?> { ["reportId"] = reportId, ["errorCode"] = error.Code });
            }
        }
        finally { _queueGate.Release(); }
    }

    private void MailLog(EmailDeliveryEntity delivery, string eventCode, SyslogSeverity severity) =>
        logs?.Publish("honeypot-mail", eventCode, severity, new Dictionary<string, object?>
        {
            ["deliveryId"] = delivery.Id, ["reportId"] = delivery.ReportSnapshotId,
            ["kind"] = delivery.Kind, ["status"] = delivery.Status, ["errorCode"] = delivery.LastErrorCode,
            ["attempt"] = delivery.AutomaticAttemptCount,
        });

    private static async Task EnsureQueueCapacityAsync(HoneypotDbContext db, int incoming, CancellationToken cancellationToken)
    {
        var count = await db.Set<EmailDeliveryEntity>().CountAsync(row => row.Status == "Pending" || row.Status == "Retrying" || row.Status == "Sending", cancellationToken);
        if (count + incoming > 1000) throw new NotificationException("QUEUE_FULL", "待发送邮件过多，请处理现有任务后再试。");
    }

    private static string[] ResolveRecipients(string[] configured, string[] fallback)
    {
        if (configured is null) throw new NotificationException("VALIDATION_ERROR", "收件人列表不能为空值。");
        var recipients = NotificationSettingsValidation.NormalizeRecipients(configured.Length == 0 ? fallback : configured);
        if (recipients.Length == 0) throw new NotificationException("VALIDATION_ERROR", "请至少配置一位收件人。");
        return recipients;
    }
    private static void EnsureEnabled(NotificationSettings settings)
    {
        if (!settings.Enabled) throw new NotificationException("NOTIFICATIONS_DISABLED", "请先启用邮件通知。");
    }
    private static NotificationException RateLimited(string message) => new("RATE_LIMITED", message);
    private static void ValidatePage(int page, int pageSize)
    {
        if (page is < 1 or > 1000000 || pageSize is < 1 or > 100) throw new NotificationException("VALIDATION_ERROR", "分页参数无效。");
    }
    public static string ReportTitle(string kind) => kind switch { "Daily" => "蜜罐运行日报", "Weekly" => "蜜罐运行周报", "Monthly" => "蜜罐运行月报", _ => "蜜罐运行报告" };
    private static DateTimeOffset Utc(long value) => DateTimeOffset.FromUnixTimeMilliseconds(value);
    private static DateTimeOffset? NullableUtc(long? value) => value.HasValue ? Utc(value.Value) : null;
    private static EmailDeliverySummary Summary(EmailDeliveryEntity item, ReportSnapshotEntity? snapshot) => new()
    {
        Id = item.Id, Kind = item.Kind, Recipient = item.Recipient, Subject = item.Subject, Status = item.Status,
        CreatedAtUtc = Utc(item.CreatedUnixMs), SentAtUtc = NullableUtc(item.AcceptedUnixMs), NextAttemptAtUtc = NullableUtc(item.NextAttemptUnixMs),
        AttemptCount = item.AttemptCount, LastErrorCode = item.LastErrorCode, LastErrorMessage = item.LastErrorMessage,
        ReportId = item.ReportSnapshotId, PeriodStartAtUtc = NullableUtc(snapshot?.PeriodStartUnixMs), PeriodEndAtUtc = NullableUtc(snapshot?.PeriodEndUnixMs)
    };
}
