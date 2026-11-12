using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Nodes;
using Honeypot.Api.Models;

namespace Honeypot.Api.Common;

internal sealed class McpHttpAuditState(HttpContext http, string? sourceIp, string? credential)
{
    private readonly DateTimeOffset startedAt = DateTimeOffset.UtcNow;
    private readonly long startTick = Stopwatch.GetTimestamp();
    private string? clientName;
    private string? requestId;
    private string? requestParameters;
    private string? tool;
    private string? method;
    private string? protocol = McpAuditPayload.Text(http.Request.Headers["MCP-Protocol-Version"].FirstOrDefault(), credential, 40);
    private string? requestHeaders;
    private bool requestHeadersTruncated;

    public McpApiKey? Key { get; set; }
    public string? PersistedAuditId { get; set; }
    public string? Result { get; set; }
    public string? ErrorCode { get; set; }
    public string? ErrorMessage { get; set; }
    public string? RequestBodyOmittedReason { get; set; }
    public bool HasDuplicateRequestFields { get; private set; }
    public long? RequestBytes { get; set; } = http.Request.ContentLength;
    public string? Credential => credential;

    public void CaptureRequestHeaders() =>
        requestHeaders = McpAuditPayload.Headers(http.Request.Headers, credential, out requestHeadersTruncated);

    public void ReadRequest(ReadOnlyMemory<byte> body)
    {
        if (body.IsEmpty) return;
        try
        {
            using var doc = JsonDocument.Parse(body);
            var request = doc.RootElement;
            if (request.ValueKind != JsonValueKind.Object)
            {
                RequestBodyOmittedReason = "INVALID_ENVELOPE";
                return;
            }
            if (ContainsDuplicateFields(request))
            {
                HasDuplicateRequestFields = true;
                RequestBodyOmittedReason = "DUPLICATE_FIELDS";
                return;
            }

            method = ReadString(request, "method", 100);
            if (Get(request, "id") is { } id)
                requestId = id.ValueKind switch
                {
                    JsonValueKind.String => McpAuditPayload.Text(id.GetString(), credential),
                    JsonValueKind.Number => McpAuditPayload.Text(id.GetRawText(), credential),
                    _ => null,
                };
            if (Get(request, "params") is not { ValueKind: JsonValueKind.Object } parameters) return;

            var meta = Get(request, "_meta") ?? Get(parameters, "_meta");
            if (meta is { } values)
            {
                if (Get(values, "io.modelcontextprotocol/clientInfo") is { } info) clientName = ReadString(info, "name");
                protocol ??= ReadString(values, "io.modelcontextprotocol/protocolVersion", 40);
            }

            if (method == "tools/call")
            {
                tool = ReadString(parameters, "name", 100);
                if (tool is not null && McpToolCatalog.TryGet(tool, out var descriptor))
                    requestParameters = ProjectToolParameters(parameters, descriptor);
                else
                    RequestBodyOmittedReason = "UNKNOWN_TOOL";
            }
            else if (method is "initialize" or "server/discover" or "tools/list" or "ping")
            {
                protocol ??= ReadString(parameters, "protocolVersion", 40);
                if (Get(parameters, "clientInfo") is { } info) clientName ??= ReadString(info, "name");
                var projected = new JsonObject();
                foreach (var field in parameters.EnumerateObject())
                {
                    if (field.Name is "protocolVersion" or "clientInfo" or "capabilities" or "cursor" or "_meta")
                        projected[field.Name] = JsonNode.Parse(McpAuditPayload.Json(field.Value, credential)!);
                    else
                        RequestBodyOmittedReason = "UNRECOGNIZED_PARAMETERS_OMITTED";
                }
                requestParameters = projected.ToJsonString();
            }
            else
            {
                RequestBodyOmittedReason = "UNSUPPORTED_METHOD_BODY";
            }
        }
        catch (JsonException)
        {
            RequestBodyOmittedReason = "INVALID_JSON";
        }
    }

    public McpAuditEntry Snapshot(McpResponseCapture? captured = null, bool pending = false)
    {
        var status = http.Response.StatusCode;
        string? responseHeaders = null, responseBody = null, responseOmitted = null;
        var responseHeadersTruncated = false;
        if (!pending)
        {
            responseHeaders = McpAuditPayload.Headers(http.Response.Headers, credential, out responseHeadersTruncated);
            if (captured is not null)
            {
                if (captured.Written > McpAuditPayload.MaxResponseBytes)
                    responseOmitted = "RESPONSE_LIMIT";
                else
                    responseBody = McpAuditPayload.Response(captured.Body, http.Response.ContentType, credential, out responseOmitted);
                if (Result is null && responseBody is not null)
                    ReadProtocolOutcome(responseBody);
            }
        }

        return new()
        {
            OccurredAtUtc = startedAt,
            HttpMethod = McpAuditPayload.Text(http.Request.Method, credential, 16)!,
            Path = "/mcp",
            Result = pending ? McpAuditResult.Pending : Result ??
                (status < 400 ? McpAuditResult.Success : McpAuditResult.ProtocolError),
            SourceIp = sourceIp,
            ClientName = clientName,
            McpMethod = method,
            ProtocolVersion = protocol,
            RequestId = requestId,
            TraceId = Activity.Current?.TraceId.ToString() ?? McpAuditPayload.Text(http.TraceIdentifier, credential),
            KeyId = Key?.Id,
            KeyName = McpAuditPayload.Text(Key?.Name, credential),
            KeyPrefix = Key?.Prefix,
            ToolName = tool,
            HttpStatus = pending ? null : status,
            ErrorCode = ErrorCode,
            ErrorMessage = McpAuditPayload.Text(ErrorMessage, credential, 500),
            ElapsedMs = pending ? null : (long)Stopwatch.GetElapsedTime(startTick).TotalMilliseconds,
            RequestBytes = RequestBytes,
            ResponseBytes = pending ? null : captured?.Written,
            RequestHeaders = requestHeaders,
            RequestParameters = requestParameters,
            ResponseHeaders = responseHeaders,
            ResponseBody = responseBody,
            CaptureNote = requestHeadersTruncated || responseHeadersTruncated ? "HEADERS_LIMIT" : null,
            RequestBodyOmittedReason = RequestBodyOmittedReason,
            ResponseBodyOmittedReason = responseOmitted,
        };
    }

    private string ProjectToolParameters(JsonElement parameters, McpToolDescriptor descriptor)
    {
        var projected = new JsonObject { ["name"] = descriptor.Name };
        if (Get(parameters, "arguments") is { ValueKind: JsonValueKind.Object } arguments)
        {
            var allowed = descriptor.InputSchema.GetProperty("properties");
            var sanitized = new JsonObject();
            foreach (var field in arguments.EnumerateObject())
            {
                if (McpToolArguments.IsValidField(allowed, field))
                    sanitized[field.Name] = JsonNode.Parse(McpAuditPayload.Json(field.Value, credential)!);
                else
                    RequestBodyOmittedReason = "UNRECOGNIZED_ARGUMENTS_OMITTED";
            }
            projected["arguments"] = sanitized;
        }
        return projected.ToJsonString();
    }

    private void ReadProtocolOutcome(string response)
    {
        // 兼容老客户端的 SSE 以及新客户端的 JSON 响应。
        var json = response.TrimStart().StartsWith('{')
            ? response
            : response.Split('\n').LastOrDefault(line => line.StartsWith("data: ", StringComparison.Ordinal))?[6..];
        if (json is null) return;
        using var document = JsonDocument.Parse(json);
        var envelope = document.RootElement;
        if (Get(envelope, "error") is { ValueKind: JsonValueKind.Object } error)
        {
            Result = McpAuditResult.ProtocolError;
            ErrorCode = Get(error, "code")?.GetRawText();
            ErrorMessage = ReadString(error, "message", 500);
        }
        if (Get(envelope, "result") is { } result)
        {
            protocol ??= ReadString(result, "protocolVersion", 40);
            if (Get(result, "isError") is { ValueKind: JsonValueKind.True }) Result = McpAuditResult.ToolError;
        }
    }

    private string? ReadString(JsonElement obj, string name, int limit = 150) =>
        Get(obj, name) is { ValueKind: JsonValueKind.String } element ? McpAuditPayload.Text(element.GetString(), credential, limit) : null;

    private static JsonElement? Get(JsonElement obj, string property) =>
        obj.ValueKind == JsonValueKind.Object && obj.TryGetProperty(property, out var value) ? value : null;

    private static bool ContainsDuplicateFields(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Array)
            return element.EnumerateArray().Any(ContainsDuplicateFields);
        if (element.ValueKind != JsonValueKind.Object) return false;
        // 审计和 SDK 必须对请求含义有一致理解，因此拒绝重复 JSON 属性。
        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (var field in element.EnumerateObject())
            if (!names.Add(field.Name) || ContainsDuplicateFields(field.Value)) return true;
        return false;
    }
}
