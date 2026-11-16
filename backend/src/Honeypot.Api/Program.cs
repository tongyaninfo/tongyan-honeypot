using Honeypot.Api.Models;
using Honeypot.Api.Common;
using Honeypot.Api.Service;
using Honeypot.Api.Service.impl;
using Honeypot.Api.Data;
using Honeypot.Api.Workers;
using Honeypot.Api.Realtime;
using Honeypot.Api.Middleware;
using Honeypot.Api.Options;
using Honeypot.Engine.Service;
using Honeypot.Engine.Service.impl;
using Honeypot.Protocol.Abstractions.Models;
using Honeypot.Protocol.Abstractions.Service;
using Honeypot.Protocols.Builtin;
using Honeypot.Runtime.Service;
using Honeypot.Shared.Models;
using Microsoft.EntityFrameworkCore;

if (args is ["--probe-management-health"])
{
    Environment.ExitCode = await ManagementHttps.ProbeLoopbackAsync();
    return;
}

var builder = WebApplication.CreateBuilder(args);
builder.UseManagementHttps();
builder.Services.AddSingleton<ISyslogSettingsStore, FileSyslogSettingsStore>();
builder.Services.AddSingleton<SyslogQueue>();
builder.Services.AddSingleton<ISyslogPublisher>(services => services.GetRequiredService<SyslogQueue>());
builder.Services.AddSingleton<SyslogDeliveryWorker>();
builder.Services.AddSingleton<ISyslogDeliveryService>(services => services.GetRequiredService<SyslogDeliveryWorker>());
builder.Services.AddHostedService(services => services.GetRequiredService<SyslogDeliveryWorker>());
builder.Services.AddSingleton<ILoggerProvider, SyslogLoggerProvider>();
builder.Logging.AddFilter<SyslogLoggerProvider>(null, LogLevel.Trace);
// MCP 正文只进入受控调用审计，不交由 SDK 或 Syslog 的诊断日志记录。
builder.Logging.AddFilter("ModelContextProtocol", LogLevel.None);
builder.Logging.AddFilter<SyslogLoggerProvider>("ModelContextProtocol", LogLevel.None);
builder.Services.AddSingleton<IThreatDecisionEngine, ThreatDecisionEngine>();
builder.Services.AddSingleton<IUserIdentityService, FileUserIdentityService>();
builder.Services.AddIPLocation();
builder.Services.AddConnectionMapTarget();
var databasePath = HoneypotDbOptions.ResolveDatabasePath(builder.Configuration, builder.Environment);
builder.Services.AddDbContextFactory<HoneypotDbContext>(options => options.UseSqlite($"Data Source={databasePath};Cache=Shared;Foreign Keys=True"));
builder.Services.AddHostedService<HoneypotDbInitializer>();
builder.Services.AddHoneypotRuntime();
builder.Services.AddSingleton<ServiceInstanceOperations>();
builder.Services.AddBuiltinProtocolAdapters();
builder.Services.AddSingleton<IServiceInstanceStore, SqliteServiceInstanceStore>();
builder.Services.AddOptions<CredentialEvidenceOptions>().BindConfiguration(CredentialEvidenceOptions.SectionName)
    .ValidateDataAnnotations().ValidateOnStart();
builder.Services.AddSingleton<CredentialEvidenceKeys>();
builder.Services.AddSingleton<ICredentialEvidenceStore, SqliteCredentialEvidenceStore>();
builder.Services.AddSingleton<ICredentialEvidenceAccessService, CredentialEvidenceAccessService>();
builder.Services.AddHostedService<CredentialEvidenceRetentionWorker>();
builder.Services.AddSingleton<ManagementOperationAuditStore>();
// 写入事务完成后才进入实时广播。邮件外发由独立后台任务执行。
builder.Services.AddHoneypotReports();
builder.Services.AddHostedService<ServiceInstanceRecoveryWorker>();
builder.Services.AddSingleton<SqliteReportService>();
builder.Services.AddSingleton<IReportService, ReportWithMailSummaryService>();
builder.Services.AddSingleton<IResourceIdGenerator, ResourceIdGenerator>();
builder.Services.AddHoneypotNotifications();
// 事件存储注册完成后再接管 IInteractionEventSink，确保先记录再实时广播。
builder.Services.AddHoneypotRealtime();
builder.Services.AddSingleton<IProtocolAdapterRegistry>(services =>
{
    var registry = new Honeypot.Runtime.Service.ProtocolAdapterRegistry();
    foreach (var adapter in services.GetServices<IHoneypotServiceAdapter>())
    {
        registry.Register(adapter);
    }

    return registry;
});
builder.Services.AddCors(options => options.AddPolicy("local-development", policy =>
    policy.AllowAnyHeader().AllowAnyMethod().WithOrigins("http://localhost:8000")));
builder.Services.AddHoneypotMcpPersistence();
builder.Services.AddHoneypotMcpTransport(builder.Configuration);

var app = builder.Build();
var syslog = app.Services.GetRequiredService<ISyslogPublisher>();
syslog.Publish("honeypot-host", "HOST_STARTING", SyslogSeverity.Notice);
app.Lifetime.ApplicationStarted.Register(() => syslog.Publish("honeypot-host", "HOST_READY", SyslogSeverity.Notice));
app.Lifetime.ApplicationStopping.Register(() => syslog.Publish("honeypot-host", "HOST_STOPPING", SyslogSeverity.Notice));
app.UseHoneypotMcpTransport();
app.UseMiddleware<SyslogRequestAuditMiddleware>();
app.UseDefaultFiles();
app.UseStaticFiles(new StaticFileOptions
{
    OnPrepareResponse = file =>
    {
        // 地图来源说明使用 UTF-8，显式声明字符集以避免浏览器误判中文。
        if (file.Context.Request.Path.Equals("/assets/maps/attribution.txt", StringComparison.OrdinalIgnoreCase))
            file.Context.Response.ContentType = "text/plain; charset=utf-8";
    },
});
app.UseCors("local-development");

// SignalR 的 WebSocket 请求不一定携带普通 HTTP Authorization 头，
// 这里允许当前会话令牌通过 access_token 握手，并在进入 Hub 前完成鉴权。
app.Use(async (context, next) =>
{
    if (!context.Request.Path.StartsWithSegments("/hubs/honeypot"))
    {
        await next();
        return;
    }

    var identity = context.RequestServices.GetRequiredService<IUserIdentityService>();
    var authorization = context.Request.Headers.Authorization.ToString();
    var token = authorization.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)
        ? authorization[7..].Trim()
        : context.Request.Query["access_token"].FirstOrDefault();
    if (!identity.IsInitialized)
    {
        context.Response.StatusCode = StatusCodes.Status428PreconditionRequired;
        await context.Response.WriteAsJsonAsync(ApiResult<object>.Fail("INITIAL_SETUP_REQUIRED", "请先完成首次初始化。"));
        return;
    }

    if (string.IsNullOrWhiteSpace(token) || !identity.TryAuthenticate(token, out var user) || user is null)
    {
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        await context.Response.WriteAsJsonAsync(ApiResult<object>.Fail("UNAUTHORIZED", "登录已失效，请重新登录。"));
        return;
    }

    context.Items["CurrentUser"] = user;
    await next();
});

app.Use(async (context, next) =>
{
    if (!context.Request.Path.StartsWithSegments("/api"))
    {
        await next();
        return;
    }

    var path = context.Request.Path.Value ?? string.Empty;
    if (context.Request.Path.StartsWithSegments(PasswordBookEndpoints.Path) ||
        context.Request.Path.StartsWithSegments(OverviewConnectionMapEndpoints.Path))
        context.Response.Headers.CacheControl = "no-store";
    var openEndpoint = path.Equals("/api/v1/setup/status", StringComparison.OrdinalIgnoreCase)
        || path.Equals("/api/v1/setup/initialize", StringComparison.OrdinalIgnoreCase)
        || path.Equals("/api/v1/auth/login", StringComparison.OrdinalIgnoreCase)
        || path.Equals("/api/v1/auth/logout", StringComparison.OrdinalIgnoreCase);
    if (openEndpoint)
    {
        await next();
        return;
    }

    var identity = context.RequestServices.GetRequiredService<IUserIdentityService>();
    if (!identity.IsInitialized)
    {
        context.Response.StatusCode = StatusCodes.Status428PreconditionRequired;
        await context.Response.WriteAsJsonAsync(ApiResult<object>.Fail("INITIAL_SETUP_REQUIRED", "请先完成首次初始化。"));
        return;
    }

    var authorization = context.Request.Headers.Authorization.ToString();
    var token = authorization.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase) ? authorization[7..].Trim() : string.Empty;
    if (!identity.TryAuthenticate(token, out var user) || user is null)
    {
        CredentialEvidenceEndpoints.AuditUnauthenticatedRead(context);
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        await context.Response.WriteAsJsonAsync(ApiResult<object>.Fail("UNAUTHORIZED", "登录已失效，请重新登录。"));
        return;
    }

    context.Items["CurrentUser"] = user;
    await next();
});

app.UseMiddleware<ManagementOperationAuditMiddleware>();

app.MapGet("/health", () => Results.Ok(ApiResult<HealthStatus>.Ok(
    new HealthStatus("Honeypot.Api", "0.1.0", DateTimeOffset.UtcNow))));

app.MapGet("/api/v1/setup/status", (IUserIdentityService identity) =>
    Results.Ok(ApiResult<object>.Ok(new { initialized = identity.IsInitialized, requiresSetup = !identity.IsInitialized })));

app.MapPost("/api/v1/setup/initialize", async (InitializeAdminRequest request, IUserIdentityService identity, HttpContext context,
    CancellationToken cancellationToken) =>
{
    var result = await identity.InitializeFirstAdminAsync(request.Username, request.Password, cancellationToken);
    if (result.Succeeded && identity.GetUsers().SingleOrDefault() is { } admin)
    {
        context.Items["CurrentUser"] = admin;
        ManagementOperationAuditMiddleware.SetResourceId(context, admin.UserId);
    }
    return result.Succeeded
        ? Results.Ok(ApiResult<object>.Ok(new { initialized = true, message = result.Message }))
        : Results.BadRequest(ApiResult<object>.Fail(result.Code, result.Message));
});

app.MapPost("/api/v1/auth/login", async (LoginRequest request, IUserIdentityService identity, HttpContext context, TimeProvider clock, CancellationToken cancellationToken) =>
{
    var result = await identity.LoginAsync(request.Username, request.Password, cancellationToken);
    context.Response.Headers.CacheControl = "no-store";
    if (result.LockedUntilUtc is { } lockedUntil)
    {
        if (result.LockoutStarted) ManagementOperationAuditMiddleware.MarkLoginLockoutStarted(context);
        var seconds = Math.Max(1, (int)Math.Ceiling((lockedUntil - clock.GetUtcNow()).TotalSeconds));
        context.Response.Headers.RetryAfter = seconds.ToString(System.Globalization.CultureInfo.InvariantCulture);
        var minutes = (seconds + 59) / 60;
        return Results.Json(ApiResult<object>.Fail("LOGIN_LOCKED", $"系统登录已锁定，请在约 {minutes} 分钟后重试。"),
            statusCode: StatusCodes.Status429TooManyRequests);
    }
    if (result.Busy)
    {
        context.Response.Headers.RetryAfter = "1";
        return Results.Json(ApiResult<object>.Fail("LOGIN_BUSY", "登录请求过多，请稍后重试。"),
            statusCode: StatusCodes.Status429TooManyRequests);
    }
    if (result.Session is not { } session)
        return Results.Json(ApiResult<object>.Fail("INVALID_CREDENTIALS", "用户名或密码错误。"), statusCode: StatusCodes.Status401Unauthorized);

    context.Items["CurrentUser"] = session.User;
    return Results.Ok(ApiResult<LoginResult>.Ok(session));
});

app.MapGet("/api/v1/auth/me", (HttpContext context) =>
{
    var user = context.Items["CurrentUser"] as AuthenticatedUser;
    return user is null ? Results.Unauthorized() : Results.Ok(ApiResult<AuthenticatedUser>.Ok(user));
});

app.MapPost("/api/v1/auth/logout", (HttpRequest request, IUserIdentityService identity) =>
{
    var authorization = request.Headers.Authorization.ToString();
    var token = authorization.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase) ? authorization[7..].Trim() : string.Empty;
    if (!string.IsNullOrEmpty(token) && identity.TryAuthenticate(token, out var user)) request.HttpContext.Items["CurrentUser"] = user;
    identity.Logout(token);
    return Results.Ok(ApiResult<object>.Ok(new { loggedOut = true }));
});

app.MapGet("/api/v1/users", (IUserIdentityService identity) =>
    Results.Ok(ApiResult<IReadOnlyCollection<AuthenticatedUser>>.Ok(identity.GetUsers())));

app.MapGet("/", () => Results.Redirect("/index.html"));

app.MapPost("/api/v1/events/preview", (HoneypotObservation observation, IThreatDecisionEngine engine) =>
{
    var decision = engine.Evaluate(observation);
    syslog.Publish("honeypot-engine", "THREAT_DECISION_PREVIEW", SyslogSeverity.Debug,
        new Dictionary<string, object?> { ["decision"] = decision.Decision.ToString() });
    return Results.Ok(ApiResult<object>.Ok(new
    {
        observation,
        decision.Decision,
        decision.Reason,
        decision.EvaluatedAtUtc,
    }));
});

app.MapGet("/api/v1/service-types", (IProtocolAdapterRegistry registry) =>
    Results.Ok(ApiResult<IReadOnlyCollection<ServiceAdapterDescriptor>>.Ok(
        registry.GetAll().Select(adapter => adapter.Descriptor).ToArray())));

app.MapGet("/api/v1/service-types/{adapterKey}/capabilities", (string adapterKey, IProtocolAdapterRegistry registry) =>
    registry.TryGet(adapterKey, out var adapter) && adapter is not null
        ? Results.Ok(ApiResult<ServiceAdapterDescriptor>.Ok(adapter.Descriptor))
        : Results.NotFound(ApiResult<object>.Fail("NOT_FOUND", $"Adapter '{adapterKey}' was not found.")));

app.MapGet("/api/v1/service-instances", (IServiceInstanceStore store) =>
    Results.Ok(ApiResult<IReadOnlyCollection<ServiceInstance>>.Ok(store.GetAll())));

app.MapPost("/api/v1/service-instances", async (ServiceInstance instance, ServiceInstanceOperations operations, HttpContext context,
    CancellationToken cancellationToken) =>
{
    if (instance.Bindings.Count == 0)
    {
        return Results.BadRequest(ApiResult<object>.Fail("VALIDATION_ERROR", "At least one listener binding is required."));
    }

    var saved = await operations.SaveAsync(instance, cancellationToken);
    ManagementOperationAuditMiddleware.SetResourceId(context, saved.InstanceId);
    return Results.Ok(ApiResult<ServiceInstance>.Ok(saved));
});

app.MapGet("/api/v1/service-instances/{instanceId}", (string instanceId, IServiceInstanceStore store) =>
{
    var instance = store.Get(instanceId);
    return instance is null
        ? Results.NotFound(ApiResult<object>.Fail("NOT_FOUND", $"Instance '{instanceId}' was not found."))
        : Results.Ok(ApiResult<ServiceInstance>.Ok(instance));
});

app.MapPost("/api/v1/service-instances/{instanceId}/apply", async (
    string instanceId,
    ServiceInstanceOperations operations,
    HttpContext context,
    CancellationToken cancellationToken) =>
{
    var operation = await operations.ExecuteAsync(instanceId, ServiceInstanceAction.Apply, cancellationToken);
    if (operation.Instance is null)
    {
        return Results.NotFound(ApiResult<object>.Fail("NOT_FOUND", $"Instance '{instanceId}' was not found."));
    }

    ManagementOperationAuditMiddleware.SetResourceId(context, operation.Instance.InstanceId);
    var result = operation.ListenerResult!;
    return result.Succeeded
        ? Results.Ok(ApiResult<ListenerApplyResult>.Ok(result))
        : Results.Conflict(ApiResult<ListenerApplyResult>.Fail(result.Code, result.Message));
});

app.MapPost("/api/v1/service-instances/{instanceId}/start", async (
    string instanceId,
    ServiceInstanceOperations operations,
    HttpContext context,
    CancellationToken cancellationToken) =>
{
    var operation = await operations.ExecuteAsync(instanceId, ServiceInstanceAction.Start, cancellationToken);
    if (operation.Instance is null)
    {
        return Results.NotFound(ApiResult<object>.Fail("NOT_FOUND", $"Instance '{instanceId}' was not found."));
    }

    ManagementOperationAuditMiddleware.SetResourceId(context, operation.Instance.InstanceId);
    var result = operation.ListenerResult!;
    return result.Succeeded
        ? Results.Ok(ApiResult<ListenerApplyResult>.Ok(result))
        : Results.Conflict(ApiResult<ListenerApplyResult>.Fail(result.Code, result.Message));
});

app.MapPost("/api/v1/service-instances/{instanceId}/stop", async (
    string instanceId,
    ServiceInstanceOperations operations,
    HttpContext context,
    CancellationToken cancellationToken) =>
{
    var operation = await operations.ExecuteAsync(instanceId, ServiceInstanceAction.Stop, cancellationToken);
    if (operation.Instance is null)
    {
        return Results.NotFound(ApiResult<object>.Fail("NOT_FOUND", $"Instance '{instanceId}' was not found."));
    }

    ManagementOperationAuditMiddleware.SetResourceId(context, operation.Instance.InstanceId);
    return Results.Ok(ApiResult<object>.Ok(new { instanceId, state = "Stopped" }));
});

app.MapPost("/api/v1/service-instances/{instanceId}/restart-policy", async (
    string instanceId,
    RestartPolicyRequest request,
    ServiceInstanceOperations operations,
    HttpContext context,
    CancellationToken cancellationToken) =>
{
    var operation = await operations.ExecuteAsync(instanceId, ServiceInstanceAction.SetRestartPolicy, cancellationToken, request.AutoStart);
    if (operation.Instance is null)
    {
        return Results.NotFound(ApiResult<object>.Fail("NOT_FOUND", $"Instance '{instanceId}' was not found."));
    }

    ManagementOperationAuditMiddleware.SetResourceId(context, operation.Instance.InstanceId);
    return Results.Ok(ApiResult<ServiceInstance>.Ok(operation.Instance));
});

app.MapGet("/api/v1/listeners", (IListenerHost listenerHost) =>
    Results.Ok(ApiResult<IReadOnlyCollection<ListenerRuntimeStatus>>.Ok(listenerHost.GetStatuses())));

app.MapInteractionEventEndpoints();
app.MapThreatEndpoints();
app.MapCredentialEvidenceEndpoints();
app.MapPasswordBookEndpoints();
app.MapManagementOperationAuditEndpoints();

app.MapGet("/api/v1/metrics/summary", (IInteractionEventStore events, IThreatProfileStore threats, IListenerHost listenerHost, ReportIngestionHealth ingestion) =>
{
    var allEvents = events.GetAll();
    return Results.Ok(ApiResult<object>.Ok(new
    {
        acceptedConnections = allEvents.Count(item => item.EventType == "ConnectionAccepted"),
        authenticationAttempts = allEvents.Count(item => item.EventType == "AuthenticationAttempted"),
        protocolViolations = allEvents.Count(item => item.EventType == "ProtocolViolation"),
        threatIps = threats.Count(),
        listeners = listenerHost.GetStatuses(),
        eventStorage = EventStorageMetrics.From(ingestion),
    }));
});

app.MapGet("/api/v1/metrics/overview", async (
    IInteractionEventStore events, IThreatProfileStore threats, IListenerHost listenerHost, IServiceInstanceStore instances,
    ReportIngestionHealth ingestion, SqliteReportService reports, TimeProvider clock, CancellationToken cancellationToken) =>
{
    var now = clock.GetUtcNow();
    var activity = await reports.ReadOverviewActivityAsync(now, cancellationToken);
    var metrics = OverviewMetricsReader.Read(events, threats, listenerHost, instances, now, includeHost: true);
    return Results.Ok(ApiResult<OverviewMetrics>.Ok(metrics with
    {
        ActivityByHour = activity,
        EventStorage = EventStorageMetrics.From(ingestion),
    }));
});

app.MapOverviewConnectionsEndpoints();
app.MapOverviewConnectionMapEndpoints();

app.MapHub<HoneypotHub>("/hubs/honeypot");
app.MapIPLocationEndpoints();
app.MapNotificationEndpoints();
app.MapSyslogEndpoints();
app.MapMcpManagementEndpoints();
app.MapHoneypotMcpTransport();

app.MapFallbackToFile("index.html");

app.Run();

public partial class Program;
