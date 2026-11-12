using System.Text.Json;
using Honeypot.Api.Models;

namespace Honeypot.Api.Common;

/// <summary>管理台权限叶子和 MCP 工具均使用这里的稳定名称及参数合同。</summary>
public static class McpToolCatalog
{
    private const string Overview = "overview";
    private const string Instances = "instances";
    private const string Events = "events";
    private const string Threats = "threats";
    private const string Evidence = "evidence";
    private const string Reports = "reports";
    private const string SystemStatus = "system-status";
    public const int MaximumPageSize = 50;
    public const int MaximumPage = 1_000_000;

    private static readonly Field InstanceId = Text("instanceId", "已保存的实例 ID", 128, required: true);
    private static readonly Field OptionalInstanceId = InstanceId with { Required = false };
    private static readonly Field SourceIp = Text("sourceIp", "规范 IPv4 或 IPv6 地址", 64);
    private static readonly Field AdapterKey = Text("adapterKey", "协议适配器标识", 64);
    private static readonly Field From = Date("fromUtc", "开始时间，包含此时刻");
    private static readonly Field To = Date("toUtc", "结束时间，不包含此时刻");
    private static readonly Field[] Page = [Integer("page", "页码，默认 1", 1, MaximumPage), Integer("pageSize", "每页条数，默认 20", 1, MaximumPageSize)];
    private static readonly Field[] ReportPeriod =
    [
        Choice("period", "报告周期，默认 day；custom 须同时提供起止时间", "day", "week", "month", "custom"),
        Date("startAtUtc", "自定义周期开始时间"), Date("endAtUtc", "自定义周期结束时间"),
    ];

    public static IReadOnlyList<McpToolDescriptor> All { get; } = Array.AsReadOnly(new[]
    {
        Read("get_overview", "查看运行总览", Overview, "读取连接、认证、协议与监听统计，以及活动趋势。"),
        Read("list_service_types", "查询协议能力", Instances, "列出内置蜜罐协议、支持的传输、拟真等级和客户端。", Page),
        Read("list_service_instances", "查询服务实例", Instances, "分页查询实例、监听数量及期望和实际状态。", [..Page, AdapterKey]),
        Read("get_service_instance", "查看服务实例", Instances, "查看已保存的实例和运行策略，分页查看绑定摘要。", [InstanceId, ..Page]),
        Read("list_listeners", "查询监听状态", Instances, "分页查看正在管理的监听器及连接计数，可按实例筛选。", [..Page, OptionalInstanceId]),
        Write("start_service_instance", "启动服务实例", Instances, "启动此 Key 已授权的隔离实例，使用管理员已保存并授权的监听配置。", true, [InstanceId]),
        Write("stop_service_instance", "停止服务实例", Instances, "停止此 Key 已授权的实例监听。", true, [InstanceId]),
        Write("set_service_restart_policy", "设置实例自动启动", Instances, "设置此 Key 已授权实例的自动启动策略；启用时校验授权的监听配置。", true,
            [InstanceId, new("autoStart", new { type = "boolean", description = "是否允许应用重启时恢复实例" }, true)]),
        Read("list_threat_events", "查询威胁事件", Events, "分页筛选威胁事件，支持按连接聚合的 activity 或逐步事件 raw。",
            [..Page, SourceIp, AdapterKey, Text("eventType", "事件类型", 64), Integer("destinationPort", "目标端口", 1, 65535),
                Choice("view", "事件视图，默认 activity", "activity", "raw"), From, To]),
        Read("get_connection_timeline", "查看连接时间线", Events, "按顺序分页查询单个连接的协议步骤和认证结果元数据。",
            [..Page, Text("connectionId", "连接 ID", 128, required: true)]),
        Read("preview_threat_decision", "预览威胁判定", Events, "使用结构化观测字段计算判定结果，不执行任何处置。",
            [SourceIp with { Required = true }, Text("sensorType", "传感器类型标识", 64, required: true),
                Integer("failedAttempts", "失败次数", 0, int.MaxValue, required: true),
                new("confidence", new { type = "number", description = "置信度", minimum = 0, maximum = 1 }, true)]),
        Read("list_threat_sources", "查询威胁来源", Threats, "分页查看来源 IP 档案，支持按风险分、状态、IP 及最近活动时间筛选。",
            [..Page, SourceIp, Integer("minimumScore", "最低风险分", 0, 100), Choice("status", "来源状态", "New", "Observed", "Suspicious"), From, To]),
        Read("get_threat_source", "查看威胁来源", Threats, "根据来源 IP 查看风险分、涉及服务、端口和活动计数。", [SourceIp with { Required = true }]),
        Read("list_credential_evidence_summaries", "查询认证证据摘要", Evidence, "分页读取证据关联标识、材料类型与留存时间。",
            [..Page, SourceIp, AdapterKey, Text("connectionId", "连接 ID", 128), From, To]),
        Read("get_operation_report", "生成运行报告", Reports, "读取今日、本周、本月或自定义时间的运行统计与采集覆盖度。", ReportPeriod),
        Read("list_report_history", "查询历史报告", Reports, "分页查询已保存的报告快照。", [..Page, Choice("kind", "报告类型", "Daily", "Weekly", "Monthly", "Custom")]),
        Read("get_report_snapshot", "查看报告快照", Reports, "按 ID 查看原生成时刻的报告快照。", [Text("reportId", "报告快照 ID", 128, required: true)]),
        Write("queue_operation_report", "排队发送运行报告", Reports, "将报告发送任务加入队列，收件人使用管理员预设名单。重试须使用相同 requestId。", false,
            [..ReportPeriod, Text("requestId", "此调用方为本次发送生成的 UUID，用于防重", 36, required: true, format: "uuid")]),
        Read("get_syslog_status", "查看 Syslog 投递状态", SystemStatus, "读取转发开关、排队和投递计数等状态摘要。"),
        Read("list_report_mail_deliveries", "查询报告邮件任务", SystemStatus, "分页读取报告邮件任务状态，不显示收件人、邮件正文或传输配置。",
            [..Page, Choice("kind", "报告类型", "Daily", "Weekly", "Monthly", "Custom"),
                Choice("status", "投递状态", "Pending", "Sending", "Accepted", "Retrying", "Failed", "Unknown"), From, To]),
    });

    private static readonly IReadOnlyDictionary<string, McpToolDescriptor> ByName = All.ToDictionary(tool => tool.Name, StringComparer.Ordinal);

    public static bool TryGet(string? name, out McpToolDescriptor descriptor)
    {
        descriptor = null!;
        return name is not null && ByName.TryGetValue(name, out descriptor!);
    }

    private static McpToolDescriptor Read(string name, string label, string group, string description, Field[]? fields = null) =>
        Tool(name, label, group, description, false, false, fields ?? []);

    private static McpToolDescriptor Write(string name, string label, string group, string description, bool requiresInstance, Field[] fields) =>
        Tool(name, label, group, description, true, requiresInstance, fields);

    private static McpToolDescriptor Tool(string name, string label, string group, string description, bool isWrite, bool requiresInstance, Field[] fields) =>
        new(name, label, group, group switch
        {
            Overview => "运行总览", Instances => "服务与监听", Events => "威胁事件", Threats => "威胁来源",
            Evidence => "认证证据", Reports => "运行报告", SystemStatus => "系统运行状态", _ => throw new ArgumentOutOfRangeException(nameof(group)),
        }, description, isWrite, requiresInstance, JsonSerializer.SerializeToElement(new
        {
            type = "object",
            properties = fields.ToDictionary(field => field.Name, field => field.Schema),
            required = fields.Where(field => field.Required).Select(field => field.Name).ToArray(),
            additionalProperties = false,
        }));

    private static Field Text(string name, string description, int maxLength, bool required = false, string? format = null) =>
        new(name, format is null ? (object)new { type = "string", description, minLength = 1, maxLength }
            : new { type = "string", description, minLength = 1, maxLength, format }, required);

    private static Field Date(string name, string description) => Text(name, description, 40, format: "date-time");

    private static Field Integer(string name, string description, int minimum, int maximum, bool required = false) =>
        new(name, new { type = "integer", description, minimum, maximum }, required);

    private static Field Choice(string name, string description, params string[] values) =>
        new(name, new { type = "string", description, @enum = values }, false);

    private sealed record Field(string Name, object Schema, bool Required);
}
