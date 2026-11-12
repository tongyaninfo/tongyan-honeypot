using System.Net;
using System.Text;
using System.Text.Json;
using Honeypot.Api.Middleware;
using Honeypot.Api.Models;
using Honeypot.Api.Options;
using Honeypot.Api.Service;
using Honeypot.Api.Service.impl;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.Options;
using ModelContextProtocol.AspNetCore;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;

namespace Honeypot.Api.Common;

public static class McpTransportExtensions
{
    private const string Path = "/mcp";
    private const int MaxToolResultBytes = 72 * 1024;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private static readonly JsonElement EmptyArguments = JsonSerializer.SerializeToElement(new { });

    public static IServiceCollection AddHoneypotMcpTransport(this IServiceCollection services, IConfiguration configuration)
    {
        services.Configure<McpTransportOptions>(configuration.GetSection("Honeypot:Mcp"));
        services.AddSingleton<McpTrafficLimiter>();
        services.AddHttpContextAccessor();
        services.AddSingleton<McpBusinessToolService>();
        services.AddMcpServer(options =>
        {
            options.ServerInfo = new() { Name = "tongyan-honeypot", Title = "通研 Honeypot MCP", Version = "1.0.0" };
            options.Handlers.ListToolsHandler = ListTools;
            options.Handlers.CallToolHandler = InvokeTool;
        })
        .WithHttpTransport(options => options.SessionMode = HttpServerSessionMode.Stateless);
        return services;
    }

    public static IApplicationBuilder UseHoneypotMcpTransport(this IApplicationBuilder app)
    {
        var configured = app.ApplicationServices.GetRequiredService<IOptions<McpTransportOptions>>().Value;
        var trustedProxies = configured.TrustedProxies.Select(value => IPAddress.TryParse(value, out var proxy) ? proxy : null)
            .OfType<IPAddress>().ToArray();
        return app.UseWhen(context => context.Request.Path.StartsWithSegments(Path), branch =>
        {
            if (trustedProxies.Length > 0)
            {
                var forwarding = new ForwardedHeadersOptions
                {
                    ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto,
                    ForwardLimit = 1,
                };
                forwarding.KnownIPNetworks.Clear();
                forwarding.KnownProxies.Clear();
                foreach (var proxy in trustedProxies) forwarding.KnownProxies.Add(proxy);
                branch.UseForwardedHeaders(forwarding);
            }
            branch.UseMiddleware<McpTransportMiddleware>();
        });
    }

    public static IEndpointConventionBuilder MapHoneypotMcpTransport(this IEndpointRouteBuilder endpoints) =>
        endpoints.MapMcp(Path);

    private static ValueTask<ListToolsResult> ListTools(RequestContext<ListToolsRequestParams> context, CancellationToken cancellationToken)
    {
        var audit = ResolveAudit(context.Services);
        var tools = audit?.Key is { } key ? McpToolCatalog.All.Where(tool => Allowed(tool, key))
            .OrderBy(tool => tool.Name, StringComparer.Ordinal)
            .Select(tool => new Tool
            {
                Name = tool.Name,
                Title = tool.DisplayName,
                Description = tool.Description,
                InputSchema = tool.InputSchema,
                Annotations = new()
                {
                    ReadOnlyHint = !tool.IsWrite,
                    IdempotentHint = true,
                    DestructiveHint = tool.Name == "stop_service_instance",
                    OpenWorldHint = tool.Name == "queue_operation_report",
                },
            }).ToArray() : [];
        return ValueTask.FromResult(new ListToolsResult { Tools = tools });
    }

    private static async ValueTask<CallToolResult> InvokeTool(RequestContext<CallToolRequestParams> context, CancellationToken cancellationToken)
    {
        var services = context.Services!;
        var audit = ResolveAudit(services);
        if (audit?.Key is not { } key)
            return Error(audit, McpAuditResult.Denied, "INVALID_API_KEY", "需要有效的 MCP API Key。");
        var call = context.Params;
        if (call is null || !McpToolCatalog.TryGet(call.Name, out var tool) || !Allowed(tool, key))
            return Error(audit, McpAuditResult.Denied, "TOOL_NOT_AUTHORIZED", "此 API Key 未获该工具权限。");

        var arguments = call.Arguments is null ? EmptyArguments : JsonSerializer.SerializeToElement(call.Arguments, JsonOptions);
        if (!McpToolArguments.TryCreate(tool.InputSchema, arguments, out _))
            return Error(audit, McpAuditResult.ToolError, "INVALID_TOOL_ARGUMENTS", "参数不符合此工具的定义。");

        if (tool.IsWrite)
        {
            try
            {
                var store = services.GetRequiredService<IMcpStore>();
                // 先持久化调用意图。数据库异常时不能执行写工具，避免产生无法追溯的变更。
                audit.PersistedAuditId = await store.BeginAuditAsync(audit.Snapshot(pending: true), cancellationToken);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (Exception exception)
            {
                services.GetRequiredService<McpAuditHealth>().ReportFailure();
                services.GetRequiredService<ILogger<McpBusinessToolService>>()
                    .LogWarning("MCP write audit could not be initialized ({FailureType})", exception.GetType().Name);
                return Error(audit, McpAuditResult.Unavailable, "AUDIT_UNAVAILABLE", "审计不可用，本次写操作未执行。");
            }
        }

        try
        {
            var grants = key.InstanceGrants.ToDictionary(grant => grant.InstanceId, grant => grant.BindingFingerprint, StringComparer.Ordinal);
            var result = await services.GetRequiredService<McpBusinessToolService>()
                .InvokeAsync(tool.Name, arguments, new(key.Id, grants), cancellationToken);
            if (!result.Success)
            {
                var outcome = result.Code switch
                {
                    "RATE_LIMITED" => McpAuditResult.RateLimited,
                    "FORBIDDEN" or "INSTANCE_SCOPE_DENIED" or "INSTANCE_BINDINGS_CHANGED" or
                        "INSTANCE_BINDINGS_NOT_ISOLATED" => McpAuditResult.Denied,
                    _ => McpAuditResult.ToolError,
                };
                return Error(audit, outcome, result.Code, McpAuditPayload.Text(result.Message, audit.Credential, 500) ?? "工具执行失败。");
            }
            var data = JsonSerializer.SerializeToElement(new { success = true, result.Code, result.Message, result.Data }, JsonOptions);
            var text = McpAuditPayload.Json(data, audit.Credential)!;
            if (Encoding.UTF8.GetByteCount(text) > MaxToolResultBytes)
                return Error(audit, McpAuditResult.ToolError, "RESULT_TOO_LARGE", "工具结果超限，请缩小查询范围或减少每页条数。");
            using var sanitized = JsonDocument.Parse(text);
            audit.Result = McpAuditResult.Success;
            return new CallToolResult
            {
                Content = [new TextContentBlock { Text = text }],
                StructuredContent = sanitized.RootElement.Clone(),
            };
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            audit.Result = McpAuditResult.Unknown;
            audit.ErrorCode = "CALL_CANCELED";
            throw;
        }
        catch (Exception exception)
        {
            services.GetRequiredService<ILogger<McpBusinessToolService>>()
                .LogWarning("MCP tool failed ({ToolName}, {FailureType})", tool.Name, exception.GetType().Name);
            return Error(audit, tool.IsWrite ? McpAuditResult.Unknown : McpAuditResult.ToolError, "TOOL_EXECUTION_FAILED",
                tool.IsWrite ? "工具未返回明确结果，请查看调用记录和业务状态。" : "工具执行失败。");
        }
    }

    private static McpHttpAuditState? ResolveAudit(IServiceProvider? services) =>
        services?.GetService<IHttpContextAccessor>()?.HttpContext?.Items[typeof(McpHttpAuditState)] as McpHttpAuditState;

    private static bool Allowed(McpToolDescriptor tool, McpApiKey key) =>
        key.PermissionIds.Contains(tool.Name, StringComparer.Ordinal) &&
        (!tool.IsWrite || key.Mode == McpAccess.ReadWrite) &&
        (!tool.RequiresInstanceScope || key.InstanceGrants.Length > 0);

    private static CallToolResult Error(McpHttpAuditState? audit, string result, string code, string message)
    {
        if (audit is not null)
        {
            audit.Result = result;
            audit.ErrorCode = code;
            audit.ErrorMessage = message;
        }
        var data = JsonSerializer.SerializeToElement(new { success = false, code, message }, JsonOptions);
        return new CallToolResult
        {
            IsError = true,
            Content = [new TextContentBlock { Text = data.GetRawText() }],
            StructuredContent = data,
        };
    }
}
