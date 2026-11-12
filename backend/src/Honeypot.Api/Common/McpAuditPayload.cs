using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Honeypot.Api.Common;

internal static partial class McpAuditPayload
{
    internal const int MaxRequestBytes = 32 * 1024;
    internal const int MaxResponseBytes = 256 * 1024;
    private const int MaxHeaderBytes = 16 * 1024;

    [GeneratedRegex(@"hp_mcp_[a-f0-9]{16}\.[A-Za-z0-9_-]{43}", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex McpSecretPattern();

    [GeneratedRegex(@"(?i:\bBearer )[A-Za-z0-9._~+/=-]{8,}", RegexOptions.CultureInvariant)]
    private static partial Regex BearerPattern();

    public static string? Text(string? value, string? credential, int limit = 200)
    {
        if (value is null) return null;
        var result = credential is { Length: >= 8 }
            ? value.Replace(credential, "[凭据未记录]", StringComparison.Ordinal)
            : value;
        result = McpSecretPattern().Replace(result, "[凭据未记录]");
        result = BearerPattern().Replace(result, "Bearer [凭据未记录]");
        return result.Length <= limit ? result : result[..limit];
    }

    public static string? Headers(IHeaderDictionary headers, string? credential, out bool truncated)
    {
        var projected = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);
        var bytes = 0;
        truncated = false;
        foreach (var (name, values) in headers)
        {
            var safeName = Text(name, credential)!;
            var sensitive = IsCredentialField(name);
            var safeValues = sensitive ? ["[凭据未记录]"] :
                values.Select(value => Text(value, credential, MaxHeaderBytes) ?? string.Empty).ToArray();
            bytes += Encoding.UTF8.GetByteCount(safeName) + safeValues.Sum(Encoding.UTF8.GetByteCount);
            if (bytes > MaxHeaderBytes)
            {
                truncated = true;
                break;
            }
            projected[safeName] = safeValues;
        }
        return projected.Count == 0 ? null : JsonSerializer.Serialize(projected);
    }

    public static string? Json(JsonElement value, string? credential) =>
        Project(value, credential)?.ToJsonString() ?? "null";

    public static string? Response(ReadOnlyMemory<byte> body, string? contentType, string? credential, out string? omitted)
    {
        omitted = null;
        if (body.IsEmpty) return null;
        try
        {
            if (contentType?.StartsWith("text/event-stream", StringComparison.OrdinalIgnoreCase) == true)
            {
                // SSE 只保留标准事件字段和通过 JSON 解析的业务数据，避免落库未知文本。
                var output = new StringBuilder();
                var events = Encoding.UTF8.GetString(body.Span).Replace("\r\n", "\n", StringComparison.Ordinal)
                    .Split("\n\n", StringSplitOptions.RemoveEmptyEntries);
                foreach (var frame in events)
                {
                    var lines = frame.Split('\n');
                    var data = string.Join('\n', lines.Where(line => line.StartsWith("data:", StringComparison.Ordinal))
                        .Select(line => line[5..].TrimStart(' ')));
                    if (data.Length == 0) continue;
                    using var json = JsonDocument.Parse(data);
                    foreach (var line in lines.Where(line => line is "event: message" || line.StartsWith("id:", StringComparison.Ordinal)))
                        output.AppendLine(Text(line, credential));
                    output.Append("data: ").AppendLine(Json(json.RootElement, credential)).AppendLine();
                }
                if (output.Length > 0) return output.ToString();
                omitted = "NO_JSON_EVENT";
                return null;
            }
            using var document = JsonDocument.Parse(body);
            return Json(document.RootElement, credential);
        }
        catch (JsonException)
        {
            omitted = "UNSTRUCTURED_RESPONSE";
            return null;
        }
    }

    private static JsonNode? Project(JsonElement value, string? credential)
    {
        switch (value.ValueKind)
        {
            case JsonValueKind.Object:
                var obj = new JsonObject();
                foreach (var field in value.EnumerateObject())
                {
                    var name = Text(field.Name, credential)!;
                    if (IsCredentialField(field.Name))
                    {
                        obj[name] = "[凭据未记录]";
                        continue;
                    }
                    if (field.NameEquals("text") && field.Value.ValueKind == JsonValueKind.String &&
                        field.Value.GetString() is { } embedded && embedded.StartsWith('{'))
                    {
                        try
                        {
                            using var parsed = JsonDocument.Parse(embedded);
                            obj[name] = Json(parsed.RootElement, credential);
                            continue;
                        }
                        catch (JsonException)
                        {
                            // 普通文本仍做凭据模式过滤。
                        }
                    }
                    obj[name] = Project(field.Value, credential);
                }
                return obj;
            case JsonValueKind.Array:
                var items = new JsonArray();
                foreach (var item in value.EnumerateArray()) items.Add(Project(item, credential));
                return items;
            case JsonValueKind.String:
                return JsonValue.Create(Text(value.GetString(), credential, MaxResponseBytes));
            case JsonValueKind.Null:
                return null;
            default:
                return JsonNode.Parse(value.GetRawText());
        }
    }

    private static bool IsCredentialField(string name)
    {
        var field = new string(name.Where(char.IsAsciiLetterOrDigit).Select(char.ToLowerInvariant).ToArray());
        return field.Contains("authorization", StringComparison.Ordinal) ||
            field.Contains("cookie", StringComparison.Ordinal) ||
            field is "secret" or "password" or "passwd" or "pwd" or "token" or "apikey" or "xapikey"
                or "credential" or "rawcredential" or "credentialcontent" or "credentialmaterial"
                or "privatekey" or "ticket" or "smtpauth" or "accesskey" or "clientsecret" or "dpop" ||
            field.EndsWith("password", StringComparison.Ordinal) ||
            field.EndsWith("passwd", StringComparison.Ordinal) ||
            field.EndsWith("secret", StringComparison.Ordinal) ||
            field.EndsWith("token", StringComparison.Ordinal) ||
            field.EndsWith("privatekey", StringComparison.Ordinal) ||
            field.EndsWith("accesskey", StringComparison.Ordinal) ||
            field.EndsWith("credential", StringComparison.Ordinal) ||
            field.EndsWith("credentials", StringComparison.Ordinal) ||
            field.EndsWith("auth", StringComparison.Ordinal) ||
            field.EndsWith("apikey", StringComparison.Ordinal);
    }
}
