using System.Net;
using System.Text.Json;

namespace Honeypot.Api.Common;

/// <summary>在执行业务前校验每个工具的参数；未声明、重复或类型错误的字段全部拒绝。</summary>
public readonly struct McpToolArguments
{
    private readonly JsonElement _arguments;

    private McpToolArguments(JsonElement arguments) => _arguments = arguments;

    public static bool TryCreate(JsonElement schema, JsonElement arguments, out McpToolArguments result)
    {
        result = default;
        if (arguments.ValueKind is not (JsonValueKind.Object or JsonValueKind.Undefined)) return false;

        var properties = schema.GetProperty("properties");
        var seen = new HashSet<string>(StringComparer.Ordinal);
        if (arguments.ValueKind == JsonValueKind.Object)
        {
            foreach (var argument in arguments.EnumerateObject())
            {
                if (!seen.Add(argument.Name) || !IsValidField(properties, argument)) return false;
            }
        }

        if (schema.GetProperty("required").EnumerateArray().Any(field => !seen.Contains(field.GetString()!))) return false;
        result = new(arguments);
        return true;
    }

    public static bool IsValidField(JsonElement properties, JsonProperty argument) =>
        properties.TryGetProperty(argument.Name, out var field) && Validate(argument, field);

    public string? String(string name) => Get(name) is { } value ? value.GetString() : null;
    public int? Int(string name) => Get(name) is { } value ? value.GetInt32() : null;
    public bool Bool(string name) => Get(name) is { } value && value.GetBoolean();
    public double Double(string name) => Get(name) is { } value ? value.GetDouble() : 0;
    public DateTimeOffset? Date(string name) => Get(name) is { } value && TryDate(value, out var parsed) ? parsed : null;
    public string? Ip(string name) => String(name) is { } value && IPAddress.TryParse(value, out var parsed) ? McpInstanceScope.Normalize(parsed).ToString() : null;
    public int Page => Int("page") ?? 1;
    public int PageSize => Int("pageSize") ?? 20;

    private JsonElement? Get(string name) => _arguments.ValueKind == JsonValueKind.Object &&
        _arguments.TryGetProperty(name, out var value) ? value : null;

    private static bool Validate(JsonProperty argument, JsonElement field) => field.GetProperty("type").GetString() switch
    {
        "string" => ValidateText(argument, field),
        "integer" => argument.Value.ValueKind == JsonValueKind.Number && argument.Value.TryGetInt32(out var number) &&
            number >= field.GetProperty("minimum").GetInt32() && number <= field.GetProperty("maximum").GetInt32(),
        "number" => argument.Value.ValueKind == JsonValueKind.Number && argument.Value.TryGetDouble(out var decimalNumber) &&
            decimalNumber >= field.GetProperty("minimum").GetDouble() && decimalNumber <= field.GetProperty("maximum").GetDouble(),
        "boolean" => argument.Value.ValueKind is JsonValueKind.True or JsonValueKind.False,
        _ => false,
    };

    private static bool ValidateText(JsonProperty argument, JsonElement field)
    {
        if (argument.Value.ValueKind != JsonValueKind.String || argument.Value.GetString() is not { Length: > 0 } value) return false;
        if (field.TryGetProperty("enum", out var options)) return options.EnumerateArray().Any(option => option.GetString() == value);
        if (value.Length > field.GetProperty("maxLength").GetInt32()) return false;
        if (argument.Name == "sourceIp") return value.AsSpan().IndexOfAny('%', '[', ']') < 0 && IPAddress.TryParse(value, out _) &&
            (value.Contains(':') || value.Count(character => character == '.') == 3);
        if (field.TryGetProperty("format", out var format)) return format.GetString() switch
        {
            "date-time" => TryDate(argument.Value, out _),
            "uuid" => Guid.TryParseExact(value, "D", out var id) && id != Guid.Empty,
            _ => false,
        };

        // 业务标识使用有限字符集。日志正文不接收未定义的自由文本字段。
        return char.IsAsciiLetterOrDigit(value[0]) && value.All(character => char.IsAsciiLetterOrDigit(character) || character is '_' or '-' or '.');
    }

    private static bool TryDate(JsonElement value, out DateTimeOffset parsed)
    {
        parsed = default;
        var text = value.GetString()!;
        var explicitOffset = text.EndsWith('Z') || (text.Length >= 6 && text[^6] is '+' or '-' && text[^3] == ':');
        return explicitOffset && value.TryGetDateTimeOffset(out parsed);
    }
}
