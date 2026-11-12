using System.Text.Json;
using Honeypot.Api.Common;
using Honeypot.Api.Models;
using Honeypot.Engine.Models;
using Honeypot.Engine.Service;
using Honeypot.Protocol.Abstractions.Models;
using Honeypot.Protocol.Abstractions.Service;
using Honeypot.Shared.Models;

namespace Honeypot.Api.Service.impl;

/// <summary>将 MCP 工具映射到既有业务服务，并限定给智能体返回的字段。</summary>
public sealed class McpBusinessToolService(IProtocolAdapterRegistry adapters, IServiceInstanceStore instances,
    IListenerHost listenerHost, ServiceInstanceOperations operations, IInteractionEventStore events, IThreatProfileStore threats,
    IThreatDecisionEngine decisionEngine, ICredentialEvidenceStore evidence, IReportService reports,
    INotificationMailService mail, ISyslogDeliveryService syslog, TimeProvider time)
{
    public async Task<ApiResult<object>> InvokeAsync(string toolName, JsonElement arguments, McpToolCallContext callContext,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!McpToolCatalog.TryGet(toolName, out var descriptor)) return Missing();
        if (!McpToolArguments.TryCreate(descriptor.InputSchema, arguments, out var args)) return Invalid();

        try
        {
            return toolName switch
            {
                "get_overview" => GetOverview(),
                "list_service_types" => ListServiceTypes(args),
                "list_service_instances" => ListInstances(args),
                "get_service_instance" => GetInstance(args),
                "list_listeners" => ListListeners(args),
                "start_service_instance" => await ChangeInstanceAsync(args, callContext, ServiceInstanceAction.Start, cancellationToken),
                "stop_service_instance" => await ChangeInstanceAsync(args, callContext, ServiceInstanceAction.Stop, cancellationToken),
                "set_service_restart_policy" => await ChangeInstanceAsync(args, callContext, ServiceInstanceAction.SetRestartPolicy, cancellationToken),
                "list_threat_events" => ListEvents(args),
                "get_connection_timeline" => GetTimeline(args),
                "preview_threat_decision" => PreviewDecision(args),
                "list_threat_sources" => ListThreats(args),
                "get_threat_source" => GetThreat(args.Ip("sourceIp")!),
                "list_credential_evidence_summaries" => ListEvidence(args),
                "get_operation_report" => Ok(ProjectReport(await reports.GenerateAsync(ReportQueryFrom(args), cancellationToken))),
                "list_report_history" => Ok(await mail.GetReportsAsync(args.Page, args.PageSize, args.String("kind"), cancellationToken)),
                "get_report_snapshot" => await GetReportAsync(args.String("reportId")!, cancellationToken),
                "queue_operation_report" => await QueueReportAsync(args, callContext.KeyId, cancellationToken),
                "get_syslog_status" => GetSyslogStatus(),
                "list_report_mail_deliveries" => await ListMailAsync(args, cancellationToken),
                _ => Missing(),
            };
        }
        catch (ArgumentException) { return Invalid(); }
        catch (NotificationException error)
        {
            // 只返回固定业务消息，避免将投递或存储详情带给智能体。
            return error.Code switch
            {
                "VALIDATION_ERROR" => Invalid(),
                "CONFLICT" => Fail("CONFLICT", "该请求标识已用于不同报告参数。"),
                "RATE_LIMITED" => Fail("RATE_LIMITED", "报告发送请求过于频繁，请稍后重试。"),
                "QUEUE_FULL" => Fail("QUEUE_FULL", "报告邮件队列已满。"),
                "NOTIFICATIONS_DISABLED" => Fail("NOTIFICATIONS_DISABLED", "管理员尚未启用报告邮件通知。"),
                _ => Fail("REPORT_SERVICE_UNAVAILABLE", "报告服务暂不可用，请联系管理员。"),
            };
        }
    }

    private ApiResult<object> GetOverview()
    {
        var metrics = OverviewMetricsReader.Read(events, threats, listenerHost, instances, time.GetUtcNow(), includeHost: false);
        return Ok(metrics with { Listeners = metrics.Listeners.Take(McpToolCatalog.MaximumPageSize).ToArray() });
    }

    private ApiResult<object> ListServiceTypes(McpToolArguments args) => Page(adapters.GetAll()
        .Select(adapter => adapter.Descriptor).OrderBy(adapter => adapter.AdapterKey, StringComparer.Ordinal), args, adapter => new
        {
            adapter.AdapterKey, adapter.DisplayName, adapter.Version, adapter.Category, adapter.SystemGroup, adapter.DefaultPort,
            adapter.SupportedTransports, adapter.SupportedFidelityLevels, adapter.SupportedClients,
        });

    private ApiResult<object> ListInstances(McpToolArguments args)
    {
        var adapter = args.String("adapterKey");
        return Page(instances.GetAll().Where(item => Matches(item.AdapterKey, adapter))
            .OrderBy(item => item.InstanceId, StringComparer.Ordinal), args, ProjectInstance);
    }

    private ApiResult<object> GetInstance(McpToolArguments args)
    {
        var item = instances.Get(args.String("instanceId")!);
        if (item is null) return Missing();
        var bindings = BuildPage(item.Bindings.OrderBy(binding => binding.ListenerId, StringComparer.Ordinal), args, binding => new
            {
                binding.ListenerId, binding.BindAddress, binding.Port, binding.Transport, binding.Enabled,
            });
        return Ok(new { instance = ProjectInstance(item), bindings });
    }

    private static object ProjectInstance(ServiceInstance item) => new
    {
        item.InstanceId, item.DisplayName, item.AdapterKey, item.DesiredState, item.AutoStart, item.CurrentState,
        item.Profile.FidelityLevel, bindingCount = item.Bindings.Count,
    };

    private ApiResult<object> ListListeners(McpToolArguments args)
    {
        var id = args.String("instanceId");
        return Page(listenerHost.GetStatuses().Where(item => Matches(item.InstanceId, id))
            .OrderBy(item => item.InstanceId, StringComparer.Ordinal).ThenBy(item => item.ListenerId, StringComparer.Ordinal), args, item => new
            {
                item.ListenerId, item.InstanceId, item.BindAddress, item.Port, item.Transport, item.State,
                item.ActiveConnections, item.AcceptedCount, item.ErrorCount,
            });
    }

    private async Task<ApiResult<object>> ChangeInstanceAsync(McpToolArguments args, McpToolCallContext context,
        ServiceInstanceAction action, CancellationToken cancellationToken)
    {
        var id = args.String("instanceId")!;
        if (!context.InstanceBindingFingerprints.TryGetValue(id, out var fingerprint) || fingerprint is not { Length: 64 })
            return Fail("INSTANCE_SCOPE_DENIED", "当前 API Key 未获此实例的操作权限。");
        var result = await operations.ExecuteAsync(id, action, cancellationToken, args.Bool("autoStart"), fingerprint);
        if (result.Instance is not { } instance) return Missing();
        if (result.AccessDeniedCode is { } code) return code == "INSTANCE_BINDINGS_CHANGED"
            ? Fail(code, "绑定配置已变化，请由管理员重新授权。")
            : Fail(code, "实例的绑定不在 MCP 允许启动的隔离地址范围内。");
        if (result.ListenerResult is { Succeeded: false } listener)
            return Fail(listener.Code, "实例启动失败，请在管理台查看监听状态。");
        return Ok(ProjectInstance(instance));
    }

    private ApiResult<object> ListEvents(McpToolArguments args)
    {
        var source = args.Ip("sourceIp");
        var adapter = args.String("adapterKey");
        var eventType = args.String("eventType");
        var port = args.Int("destinationPort");
        var (from, to) = ReadRange(args);
        var matching = events.GetAll().Where(item => Matches(item.SourceIp, source) && Matches(item.AdapterKey, adapter) &&
            (port is null || item.DestinationPort == port));
        if (args.String("view") == "raw")
            return Page(matching.Where(item => Matches(item.EventType, eventType) && InRange(item.OccurredAtUtc, from, to))
                .OrderByDescending(item => item.OccurredAtUtc).ThenByDescending(item => item.Sequence).ThenBy(item => item.EventId, StringComparer.Ordinal),
                args, item => ProjectEvent(RealtimeInteractionEvent.From(item)));
        return Page(InteractionActivityProjection.Build(matching).Where(item => Matches(item.EventType, eventType) && InRange(item.OccurredAtUtc, from, to)),
            args, ProjectEvent);
    }

    private ApiResult<object> GetTimeline(McpToolArguments args)
    {
        var id = args.String("connectionId")!;
        var steps = events.GetByConnectionId(id);
        return steps.Count == 0 ? Missing() : Page(steps, args, item => ProjectEvent(RealtimeInteractionEvent.From(item)));
    }

    // 原始载荷及用户自行填入的自由文本留在现有授权界面，不向智能体和调用审计复制。
    private static object ProjectEvent(RealtimeInteractionEvent item) => new
    {
        item.EventId, item.ConnectionId, item.Sequence, item.EventType, item.OccurredAtUtc, item.SourceIp, item.SourcePort,
        item.DestinationIp, item.DestinationPort, item.ListenerId, item.ServiceInstanceId, item.AdapterKey, item.Stage, item.Outcome,
        item.RiskDelta, item.CredentialArtifactId, item.CredentialCaptured, item.AuthenticationMethod,
        item.AuthenticationFailureCode, item.AuthenticationAttempt, item.MaterialType, item.CredentialCaptureStatus, item.CloseReason, item.EventCount,
    };

    private ApiResult<object> PreviewDecision(McpToolArguments args)
    {
        var result = decisionEngine.Evaluate(new(args.Ip("sourceIp")!, args.String("sensorType")!, args.Int("failedAttempts")!.Value,
            args.Double("confidence")));
        return Ok(new { decision = result.Decision.ToString(), result.Reason, result.EvaluatedAtUtc });
    }

    private ApiResult<object> ListThreats(McpToolArguments args)
    {
        var source = args.Ip("sourceIp");
        var minimumScore = args.Int("minimumScore") ?? 0;
        var status = args.String("status");
        var (from, to) = ReadRange(args);
        return Page(threats.GetAll().Where(item => Matches(item.SourceIp, source) && item.CurrentScore >= minimumScore &&
                Matches(item.Status, status) && InRange(item.LastSeenUtc, from, to))
            .OrderByDescending(item => item.CurrentScore).ThenByDescending(item => item.LastSeenUtc)
            .ThenBy(item => item.SourceIp, StringComparer.Ordinal), args, ProjectThreat);
    }

    private ApiResult<object> GetThreat(string source) => threats.GetByIp(source) is { } item ? Ok(ProjectThreat(item)) : Missing();

    private static object ProjectThreat(ThreatIpProfile item)
    {
        // 威胁聚合服务使用此锁更新同一对象和端口集合。
        lock (item)
            return new
            {
                item.ThreatId, item.SourceIp, item.FirstSeenUtc, item.LastSeenUtc, item.CurrentScore, item.MaxScore,
                item.ScoreVersion, item.Status, item.AttemptCount, item.SessionCount, item.ActiveSessionCount,
                item.AuthenticationAttemptCount, item.ProtocolViolationCount,
                servicesTouched = item.ServicesTouched.Order(StringComparer.Ordinal).Take(McpToolCatalog.MaximumPageSize).ToArray(),
                portsTouched = item.PortsTouched.Order().Take(McpToolCatalog.MaximumPageSize).ToArray(),
                servicesTouchedCount = item.ServicesTouched.Count, portsTouchedCount = item.PortsTouched.Count,
                item.LastEventId, item.ExpiresAtUtc,
            };
    }

    private ApiResult<object> ListEvidence(McpToolArguments args)
    {
        var source = args.Ip("sourceIp");
        var adapter = args.String("adapterKey");
        var connection = args.String("connectionId");
        var (from, to) = ReadRange(args);
        return Page(evidence.GetAll().Where(item => Matches(item.SourceIp, source) && Matches(item.AdapterKey, adapter) &&
                Matches(item.ConnectionId, connection) && InRange(item.CapturedAtUtc, from, to))
            .OrderByDescending(item => item.CapturedAtUtc).ThenBy(item => item.CredentialArtifactId, StringComparer.Ordinal), args);
    }

    private async Task<ApiResult<object>> GetReportAsync(string reportId, CancellationToken cancellationToken) =>
        await mail.GetReportAsync(reportId, cancellationToken) is { } report ? Ok(ProjectReport(report)) : Missing();

    private async Task<ApiResult<object>> QueueReportAsync(McpToolArguments args, string keyId, CancellationToken cancellationToken)
    {
        var result = await mail.QueueDefaultReportAsync(ReportQueryFrom(args), keyId, Guid.ParseExact(args.String("requestId")!, "D"), cancellationToken);
        return Ok(new { result.DeliveryIds, state = "Queued" });
    }

    private static ReportQuery ReportQueryFrom(McpToolArguments args)
    {
        var period = args.String("period") ?? "day";
        var start = args.Date("startAtUtc");
        var end = args.Date("endAtUtc");
        if (period == "custom" ? start is null || end is null || start >= end : start is not null || end is not null)
            throw new ArgumentException("报告时间与周期不匹配。");
        return new() { Period = period, StartAtUtc = start, EndAtUtc = end };
    }

    private static object ProjectReport(OperationReport report) => new
    {
        report.GeneratedAtUtc, report.Period, report.Coverage, report.Totals, report.Comparison, report.Trend, report.Protocols,
        report.Ports, report.Sources, report.AuthenticationMethods, report.RiskSignals, report.Evidence,
        regions = report.Regions.Take(McpToolCatalog.MaximumPageSize).ToArray(), regionCount = report.Regions.Count,
        report.Runtime, report.MailSummary, report.Notes,
    };

    private ApiResult<object> GetSyslogStatus()
    {
        var status = syslog.GetStatus();
        return Ok(new
        {
            status.Enabled, targetCount = status.Targets.Count, status.PausedPendingCount, status.DiscardedPausedCount,
            status.ConfigFault,
            targets = status.Targets.Select(target => new
            {
                target.TargetId, target.State, target.PendingCount, target.SentCount, target.ConfirmedCount, target.FailedCount,
                target.RetriedCount, target.DroppedCount, target.TruncatedCount, target.LastSentAtUtc, target.LastConfirmedAtUtc, target.LastErrorCode,
            }).ToArray(),
        });
    }

    private async Task<ApiResult<object>> ListMailAsync(McpToolArguments args, CancellationToken cancellationToken)
    {
        var (from, to) = ReadRange(args);
        var result = await mail.GetDeliveriesAsync(new()
        {
            Page = args.Page, PageSize = args.PageSize, Kind = args.String("kind"), Status = args.String("status"),
            FromUtc = from, ToUtc = to, ReportsOnly = true,
        }, cancellationToken);
        return Ok(new
        {
            items = result.Items.Select(item => new
            {
                item.Id, item.Kind, item.Status, item.CreatedAtUtc, item.SentAtUtc, item.NextAttemptAtUtc, item.AttemptCount,
                item.LastErrorCode, item.ReportId, item.PeriodStartAtUtc, item.PeriodEndAtUtc,
            }).ToArray(),
            result.Total, result.Page, result.PageSize,
        });
    }

    private static (DateTimeOffset? From, DateTimeOffset? To) ReadRange(McpToolArguments args)
    {
        var from = args.Date("fromUtc");
        var to = args.Date("toUtc");
        if (from >= to) throw new ArgumentException("查询起止时间无效。");
        return (from, to);
    }

    private static bool InRange(DateTimeOffset value, DateTimeOffset? from, DateTimeOffset? to) =>
        (from is null || value >= from) && (to is null || value < to);

    private static bool Matches(string value, string? filter) =>
        filter is null || string.Equals(value, filter, StringComparison.OrdinalIgnoreCase);

    private static ApiResult<object> Page<T>(IEnumerable<T> source, McpToolArguments args) => Page(source, args, item => item);

    private static ApiResult<object> Page<TSource, TResult>(IEnumerable<TSource> source, McpToolArguments args, Func<TSource, TResult> project) =>
        Ok(BuildPage(source, args, project));

    private static object BuildPage<TSource, TResult>(IEnumerable<TSource> source, McpToolArguments args, Func<TSource, TResult> project)
    {
        var page = args.Page;
        var pageSize = args.PageSize;
        var skip = (page - 1) * pageSize;
        var total = 0;
        var items = new List<TResult>(pageSize);
        foreach (var item in source)
        {
            if (total >= skip && items.Count < pageSize) items.Add(project(item));
            total++;
        }
        return new { items, total, page, pageSize };
    }

    private static ApiResult<object> Ok(object value) => ApiResult<object>.Ok(value);
    private static ApiResult<object> Fail(string code, string message) => ApiResult<object>.Fail(code, message);
    private static ApiResult<object> Missing() => Fail("NOT_FOUND", "指定资源不存在或已过期。");
    private static ApiResult<object> Invalid() => Fail("VALIDATION_ERROR", "工具参数无效，请检查字段、格式和取值范围。");
}
