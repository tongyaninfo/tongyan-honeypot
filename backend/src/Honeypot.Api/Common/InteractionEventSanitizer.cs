using System.Text;
using Honeypot.Protocol.Abstractions.Models;

namespace Honeypot.Api.Common;

internal static class InteractionEventSanitizer
{
    /// <summary>普通事件只包含限长文本，凭据材料通过独立的证据接口。事件标识保持关联。</summary>
    public static InteractionEvent Sanitize(InteractionEvent item) => item with
    {
        EventType = Limit(item.EventType, 64),
        ConnectionId = Limit(item.ConnectionId, 128),
        SourceIp = Limit(item.SourceIp, 64),
        DestinationIp = Limit(item.DestinationIp, 64),
        Transport = Limit(item.Transport, 16),
        ListenerId = Limit(item.ListenerId, 128),
        ServiceInstanceId = Limit(item.ServiceInstanceId, 128),
        AdapterKey = Limit(item.AdapterKey, 64),
        ProfileId = Limit(item.ProfileId, 128),
        Stage = Limit(item.Stage, 64),
        Outcome = Limit(item.Outcome, 64),
        ProtocolErrorCode = SafeProtocolErrorCode(item),
        PayloadSummary = SafeSummary(item),
        Username = SanitizeUsername(item.Username),
        Password = null,
        Domain = Optional(item.Domain, 128),
        Database = Optional(item.Database, 128),
        AuthenticationMethod = Optional(item.AuthenticationMethod, 64),
        AuthenticationFailureCode = Optional(item.AuthenticationFailureCode, 64),
        MaterialType = Optional(item.MaterialType, 64),
        CredentialCaptureStatus = Optional(item.CredentialCaptureStatus, 64),
        RuleVersion = Optional(item.RuleVersion, 64),
        CredentialArtifactId = Optional(item.CredentialArtifactId, 128),
    };

    public static string? SanitizeUsername(string? value) => Optional(value, 128);

    private static string? SafeProtocolErrorCode(InteractionEvent item) =>
        string.Equals(item.EventType, "ProtocolViolation", StringComparison.OrdinalIgnoreCase) &&
        string.Equals(item.AdapterKey, "mssql", StringComparison.OrdinalIgnoreCase) &&
        (item.ProtocolErrorCode is "TDS_PRELOGIN_INVALID" or "TDS_TLS_FAILED" or
            "TDS_LOGIN7_INVALID" or "TDS_INTEGRATED_AUTH_INVALID") ? item.ProtocolErrorCode : null;

    private static string? SafeSummary(InteractionEvent item)
    {
        if (!string.IsNullOrEmpty(item.Password)) return null;
        // 认证步骤只允许适配器提供的固定结果。凭据正文只能进入加密证据。
        if (InteractionActivityProjection.Priority(item.EventType) == InteractionActivityProjection.Authentication)
            return item.PayloadSummary is "Authentication rejected" or "NFS access rejected" ? item.PayloadSummary : null;
        return Optional(item.PayloadSummary, 256);
    }

    private static string? Optional(string? value, int limit) => value is null ? null : Limit(value, limit);

    private static string Limit(string value, int limit)
    {
        var text = value.AsSpan(0, Math.Min(value.Length, limit));
        if (text.Length == value.Length && text.IndexOfAnyExceptInRange(' ', '~') < 0)
            return value;

        var bounded = new StringBuilder(text.Length);
        foreach (var rune in text.EnumerateRunes())
        {
            if (!Rune.IsControl(rune)) bounded.Append(rune);
        }
        return bounded.ToString();
    }
}
