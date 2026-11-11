using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Honeypot.Shared.Models;

namespace Honeypot.Api.Common;

/// <summary>统一构造 RFC 5424 消息；控制报头、字节预算和 JSON 边界。</summary>
public static class SyslogMessageFormatter
{
    private const string HostPrefix = "tongyan-honeypot-";
    private static readonly byte[] Utf8Bom = [0xEF, 0xBB, 0xBF];

    public static string BuildHostname(string machineName)
    {
        ArgumentNullException.ThrowIfNull(machineName);
        var source = machineName.Trim();
        var safe = new string(source.Select(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '.' or '_' ? character : '-').ToArray());
        var changed = safe != machineName || source.Length == 0 || source.Length > 255 - HostPrefix.Length;
        if (!changed) return HostPrefix + safe;
        // 规范化/截断后附原名称摘要，避免中文机器名或共同长前缀发生碰撞。
        var suffix = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(machineName)))[..12].ToLowerInvariant();
        var limit = 255 - HostPrefix.Length - suffix.Length - 1;
        safe = string.IsNullOrWhiteSpace(safe.Trim('-')) ? "host" : safe;
        return HostPrefix + safe[..Math.Min(safe.Length, limit)] + "-" + suffix;
    }

    public static byte[] Format(SyslogRecord record, int facility = 16, int maxBytes = 8192, string? hostname = null)
    {
        ArgumentNullException.ThrowIfNull(record);
        if (facility is < 0 or > 23) throw new ArgumentOutOfRangeException(nameof(facility));
        if (!Enum.IsDefined(record.Severity)) throw new ArgumentOutOfRangeException(nameof(record));
        if (maxBytes is < 480 or > 65507) throw new ArgumentOutOfRangeException(nameof(maxBytes));
        hostname ??= BuildHostname(Environment.MachineName);
        if (!hostname.StartsWith(HostPrefix, StringComparison.Ordinal)) throw new ArgumentException("SYSLOG_HOSTNAME_INVALID", nameof(hostname));
        ValidateHeader(hostname, 255, nameof(hostname));
        ValidateHeader(record.AppName, 48, nameof(record.AppName));
        ValidateHeader(record.EventCode, 32, nameof(record.EventCode));
        if (string.IsNullOrEmpty(record.LogId) || record.LogId.Length > 128) throw new ArgumentException("SYSLOG_LOG_ID_INVALID", nameof(record));

        // RFC 5424 仅允许最多六位秒小数，不能直接使用有七位小数的 .NET O 格式。
        var timestamp = record.Timestamp.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'", CultureInfo.InvariantCulture);
        var header = Encoding.ASCII.GetBytes($"<{facility * 8 + (int)record.Severity}>1 {timestamp} {hostname} {record.AppName} {Environment.ProcessId.ToString(CultureInfo.InvariantCulture)} {record.EventCode} - ");
        var data = new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["schemaVersion"] = 1,
            ["logId"] = record.LogId,
            ["eventCode"] = record.EventCode,
            ["severity"] = (int)record.Severity,
            ["occurredAtUtc"] = timestamp
        };
        var optional = new List<string>();
        var suppressed = false;
        foreach (var (key, value) in record.Fields.Take(64))
        {
            // 上游负责语义白名单；这里再阻断主机字段、敏感键与任意对象序列化。
            if (!IsSafeKey(key) || data.ContainsKey(key) || !TryScalar(value, out var safeValue))
            {
                suppressed = true;
                continue;
            }
            data[key] = safeValue;
            optional.Add(key);
            if (value is string text && text.Length > 2048 || value is JsonElement { ValueKind: JsonValueKind.String } element && element.GetString()!.Length > 2048)
                data["truncated"] = true;
        }
        if (suppressed || record.Fields.Count > 64) data["fieldsSuppressed"] = true;
        byte[] json;
        while (true)
        {
            json = JsonSerializer.SerializeToUtf8Bytes(data);
            if (header.Length + Utf8Bom.Length + json.Length <= maxBytes) break;
            // 删除可选字段而非截断 JSON 字节，保证中文、转义及完整报文仍可解析。
            if (optional.Count == 0) throw new ArgumentException("SYSLOG_MESSAGE_BUDGET_TOO_SMALL", nameof(maxBytes));
            var largest = optional.MaxBy(key => JsonSerializer.SerializeToUtf8Bytes(data[key]).Length)!;
            data.Remove(largest);
            optional.Remove(largest);
            data["truncated"] = true;
        }
        var message = new byte[header.Length + Utf8Bom.Length + json.Length];
        header.CopyTo(message, 0);
        Utf8Bom.CopyTo(message, header.Length);
        json.CopyTo(message, header.Length + Utf8Bom.Length);
        return message;
    }

    private static void ValidateHeader(string value, int maximum, string parameter)
    {
        if (string.IsNullOrEmpty(value) || value.Length > maximum || value.Any(character => character is < '!' or > '~'))
            throw new ArgumentException("SYSLOG_HEADER_INVALID", parameter);
    }

    private static bool IsSafeKey(string key)
    {
        if (key.Length is 0 or > 64 || !key.All(character => char.IsAsciiLetterOrDigit(character) || character == '_')) return false;
        var lower = key.ToLowerInvariant();
        return lower is not ("hostname" or "displayhost" or "computername" or "host")
            && !new[] { "password", "secret", "token", "cookie", "authorization", "privatekey", "connectionstring", "payload", "credentialbody" }.Any(lower.Contains);
    }

    private static bool TryScalar(object? value, out object? safe)
    {
        safe = value;
        if (value is string text)
        {
            // 字段预算按字符边界限制；JSON 转义会将控制字符隔离在同一消息内。
            if (text.Length > 2048)
            {
                var length = char.IsHighSurrogate(text[2047]) ? 2047 : 2048;
                safe = text[..length];
            }
            return true;
        }
        if (value is JsonElement element)
        {
            if (element.ValueKind == JsonValueKind.String) return TryScalar(element.GetString(), out safe);
            return element.ValueKind is JsonValueKind.Number or JsonValueKind.True or JsonValueKind.False or JsonValueKind.Null;
        }
        return value is null or bool or byte or sbyte or short or ushort or int or uint or long or ulong or decimal
            || value is double doubleValue && double.IsFinite(doubleValue)
            || value is float floatValue && float.IsFinite(floatValue);
    }
}
