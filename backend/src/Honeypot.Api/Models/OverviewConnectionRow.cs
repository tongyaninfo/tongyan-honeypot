using System.Text.Json.Serialization;

namespace Honeypot.Api.Models;

/// <summary>首页连接明细的最小字段白名单。</summary>
public sealed record OverviewConnectionRow(
    string Id,
    string ConnectionId,
    DateTimeOffset OccurredAtUtc,
    string SourceIp,
    int SourcePort,
    string AdapterKey,
    int DestinationPort)
{
    // 仅认证失败明细返回账号和证据引用。密码原文由既有的受审计证据接口读取。
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Username { get; init; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? CredentialArtifactId { get; init; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? MaterialType { get; init; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? EventType { get; init; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ProtocolViolationSummary { get; init; }
}
