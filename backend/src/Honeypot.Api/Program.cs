using Honeypot.Api.Models;
using Honeypot.Api.Common;
using Honeypot.Api.Service;
using Honeypot.Api.Service.impl;
using Honeypot.Api.Data;
using Honeypot.Api.Workers;
using Honeypot.Api.Realtime;
using Honeypot.Api.Middleware;
using Honeypot.Engine.Service;
using Honeypot.Engine.Service.impl;
using Honeypot.Protocol.Abstractions.Models;
using Honeypot.Protocol.Abstractions.Service;
using Honeypot.Protocols.Builtin;
using Honeypot.Runtime.Service;
using Honeypot.Shared.Models;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddSingleton<ISyslogSettingsStore, FileSyslogSettingsStore>();
builder.Services.AddSingleton<SyslogQueue>();
builder.Services.AddSingleton<ISyslogPublisher>(services => services.GetRequiredService<SyslogQueue>());
builder.Services.AddSingleton<SyslogDeliveryWorker>();
builder.Services.AddSingleton<ISyslogDeliveryService>(services => services.GetRequiredService<SyslogDeliveryWorker>());
builder.Services.AddHostedService(services => services.GetRequiredService<SyslogDeliveryWorker>());
builder.Services.AddSingleton<ILoggerProvider, SyslogLoggerProvider>();
builder.Logging.AddFilter<SyslogLoggerProvider>(null, LogLevel.Trace);
builder.Services.AddSingleton<IThreatDecisionEngine, ThreatDecisionEngine>();
builder.Services.AddSingleton<IUserIdentityService, FileUserIdentityService>();
builder.Services.AddIPLocation();
var databasePath = HoneypotDbOptions.ResolveDatabasePath(builder.Configuration, builder.Environment);
builder.Services.AddDbContextFactory<HoneypotDbContext>(options => options.UseSqlite($"Data Source={databasePath};Cache=Shared;Foreign Keys=True"));
builder.Services.AddHostedService<HoneypotDbInitializer>();
builder.Services.AddHoneypotRuntime();
builder.Services.AddBuiltinProtocolAdapters();
builder.Services.AddSingleton<IThreatProfileStore, InMemoryThreatProfileStore>();
builder.Services.AddSingleton<IInteractionEventStore, InMemoryInteractionEventStore>();
builder.Services.AddSingleton<IInteractionEventSink>(services => services.GetRequiredService<IInteractionEventStore>());
builder.Services.AddSingleton<IServiceInstanceStore, SqliteServiceInstanceStore>();
builder.Services.AddHostedService<ServiceInstanceRecoveryWorker>();
builder.Services.AddSingleton<ICredentialEvidenceStore, InMemoryCredentialEvidenceStore>();
builder.Services.AddSingleton<ICredentialEvidenceAccessService, CredentialEvidenceAccessService>();
// 先持久化报告元数据，再进入现有内存视图和实时广播；邮件外发由独立后台任务执行。
builder.Services.AddHoneypotReports();
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

var app = builder.Build();
var syslog = app.Services.GetRequiredService<ISyslogPublisher>();
syslog.Publish("honeypot-host", "HOST_STARTING", SyslogSeverity.Notice);
app.Lifetime.ApplicationStarted.Register(() => syslog.Publish("honeypot-host", "HOST_READY", SyslogSeverity.Notice));
app.Lifetime.ApplicationStopping.Register(() => syslog.Publish("honeypot-host", "HOST_STOPPING", SyslogSeverity.Notice));
app.UseMiddleware<SyslogRequestAuditMiddleware>();
app.UseDefaultFiles();
app.UseStaticFiles();
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

app.MapGet("/health", () => Results.Ok(ApiResult<HealthStatus>.Ok(
    new HealthStatus("Honeypot.Api", "0.1.0", DateTimeOffset.UtcNow))));

app.MapGet("/api/v1/setup/status", (IUserIdentityService identity) =>
    Results.Ok(ApiResult<object>.Ok(new { initialized = identity.IsInitialized, requiresSetup = !identity.IsInitialized })));

app.MapPost("/api/v1/setup/initialize", async (InitializeAdminRequest request, IUserIdentityService identity, CancellationToken cancellationToken) =>
{
    var result = await identity.InitializeFirstAdminAsync(request.Username, request.Password, cancellationToken);
    return result.Succeeded
        ? Results.Ok(ApiResult<object>.Ok(new { initialized = true, message = result.Message }))
        : Results.BadRequest(ApiResult<object>.Fail(result.Code, result.Message));
});

app.MapPost("/api/v1/auth/login", async (LoginRequest request, IUserIdentityService identity, HttpContext context, CancellationToken cancellationToken) =>
{
    var result = await identity.LoginAsync(request.Username, request.Password, cancellationToken);
    if (result is not null) context.Items["CurrentUser"] = result.User;
    return result is null
        ? Results.Unauthorized()
        : Results.Ok(ApiResult<LoginResult>.Ok(result));
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

app.MapPost("/api/v1/service-instances", (ServiceInstance instance, IServiceInstanceStore store) =>
{
    if (instance.Bindings.Count == 0)
    {
        return Results.BadRequest(ApiResult<object>.Fail("VALIDATION_ERROR", "At least one listener binding is required."));
    }

    return Results.Ok(ApiResult<ServiceInstance>.Ok(store.Upsert(instance)));
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
    IServiceInstanceStore store,
    IListenerHost listenerHost,
    IRealtimeUpdateNotifier notifier,
    CancellationToken cancellationToken) =>
{
    var instance = store.Get(instanceId);
    if (instance is null)
    {
        return Results.NotFound(ApiResult<object>.Fail("NOT_FOUND", $"Instance '{instanceId}' was not found."));
    }

    var result = await listenerHost.ApplyAsync(instance, cancellationToken);
    await notifier.PublishRuntimeAsync(listenerHost.GetStatuses(), cancellationToken);
    return result.Succeeded
        ? Results.Ok(ApiResult<ListenerApplyResult>.Ok(result))
        : Results.Conflict(ApiResult<ListenerApplyResult>.Fail(result.Code, result.Message));
});

app.MapPost("/api/v1/service-instances/{instanceId}/start", async (
    string instanceId,
    IServiceInstanceStore store,
    IListenerHost listenerHost,
    IRealtimeUpdateNotifier notifier,
    CancellationToken cancellationToken) =>
{
    var instance = store.Get(instanceId);
    if (instance is null)
    {
        return Results.NotFound(ApiResult<object>.Fail("NOT_FOUND", $"Instance '{instanceId}' was not found."));
    }

    var result = await listenerHost.ApplyAsync(instance, cancellationToken);
    store.SetDesiredState(instanceId, "Running");
    store.SetRuntimeState(instanceId, result.Succeeded ? "Running" : "Failed", result.Succeeded ? null : result.Message);
    await notifier.PublishRuntimeAsync(listenerHost.GetStatuses(), cancellationToken);
    return result.Succeeded
        ? Results.Ok(ApiResult<ListenerApplyResult>.Ok(result))
        : Results.Conflict(ApiResult<ListenerApplyResult>.Fail(result.Code, result.Message));
});

app.MapPost("/api/v1/service-instances/{instanceId}/stop", async (
    string instanceId,
    IServiceInstanceStore store,
    IListenerHost listenerHost,
    IRealtimeUpdateNotifier notifier,
    CancellationToken cancellationToken) =>
{
    if (store.Get(instanceId) is null)
    {
        return Results.NotFound(ApiResult<object>.Fail("NOT_FOUND", $"Instance '{instanceId}' was not found."));
    }

    await listenerHost.StopInstanceAsync(instanceId, cancellationToken);
    store.SetDesiredState(instanceId, "Stopped");
    store.SetRuntimeState(instanceId, "Stopped");
    await notifier.PublishRuntimeAsync(listenerHost.GetStatuses(), cancellationToken);
    return Results.Ok(ApiResult<object>.Ok(new { instanceId, state = "Stopped" }));
});

app.MapPost("/api/v1/service-instances/{instanceId}/restart-policy", (
    string instanceId,
    RestartPolicyRequest request,
    IServiceInstanceStore store) =>
{
    var instance = store.Get(instanceId);
    if (instance is null)
    {
        return Results.NotFound(ApiResult<object>.Fail("NOT_FOUND", $"Instance '{instanceId}' was not found."));
    }

    var updated = store.SetDesiredState(instanceId, instance.DesiredState, request.AutoStart);
    return Results.Ok(ApiResult<ServiceInstance>.Ok(updated!));
});

app.MapGet("/api/v1/listeners", (IListenerHost listenerHost) =>
    Results.Ok(ApiResult<IReadOnlyCollection<ListenerRuntimeStatus>>.Ok(listenerHost.GetStatuses())));

app.MapInteractionEventEndpoints();

app.MapGet("/api/v1/threats", (IThreatProfileStore store) =>
{
    var items = store.GetAll();
    return Results.Ok(ApiResult<object>.Ok(new { items, total = items.Count, page = 1, pageSize = items.Count }));
});

app.MapGet("/api/v1/threats/by-ip/{sourceIp}", (string sourceIp, IThreatProfileStore store) =>
{
    var profile = store.GetByIp(sourceIp);
    return profile is null
        ? Results.NotFound(ApiResult<object>.Fail("NOT_FOUND", $"Threat IP '{sourceIp}' was not found."))
        : Results.Ok(ApiResult<object>.Ok(profile));
});

app.MapCredentialEvidenceEndpoints();

app.MapGet("/api/v1/metrics/summary", (IInteractionEventStore events, IThreatProfileStore threats, IListenerHost listenerHost) =>
{
    var allEvents = events.GetAll();
    return Results.Ok(ApiResult<object>.Ok(new
    {
        acceptedConnections = allEvents.Count(item => item.EventType == "ConnectionAccepted"),
        authenticationAttempts = allEvents.Count(item => item.EventType == "AuthenticationAttempted"),
        protocolViolations = allEvents.Count(item => item.EventType == "ProtocolViolation"),
        threatIps = threats.GetAll().Count,
        listeners = listenerHost.GetStatuses(),
    }));
});

app.MapGet("/api/v1/metrics/overview", (
    IInteractionEventStore events,
    IThreatProfileStore threats,
    IListenerHost listenerHost,
    IServiceInstanceStore instances) =>
{
    var now = DateTimeOffset.UtcNow;
    // 总览和导出默认以 Asia/Shanghai 展示，今日统计按同一自然日计算。
    var shanghaiOffset = TimeSpan.FromHours(8);
    var dayStart = new DateTimeOffset(now.ToOffset(shanghaiOffset).Date, shanghaiOffset);
    var nextDayStart = dayStart.AddDays(1);
    var allEvents = events.GetAll();
    var authenticationFailures = allEvents.Where(OverviewActivityProjection.IsAuthenticationFailure);
    var listeners = listenerHost.GetStatuses();
    var instanceById = instances.GetAll()
        .ToDictionary(item => item.InstanceId, StringComparer.OrdinalIgnoreCase);
    var (eventBuckets, adapterActivity, activityByHour) = OverviewActivityProjection.Build(allEvents, now);

    var listenerOverview = listeners
        .Select(listener => new ListenerOverview(
            listener.ListenerId,
            listener.InstanceId,
            instanceById.TryGetValue(listener.InstanceId, out var instance) ? instance.AdapterKey : string.Empty,
            listener.Port,
            listener.State,
            listener.ActiveConnections,
            listener.AcceptedCount,
            listener.ErrorCount))
        .ToArray();

    var metrics = new OverviewMetrics
    {
        GeneratedAtUtc = now,
        EventCount = allEvents.Count,
        AcceptedConnections = allEvents.Count(item => item.EventType.Equals("ConnectionAccepted", StringComparison.OrdinalIgnoreCase)),
        AuthenticationAttempts = allEvents.Count(item => item.EventType.Equals("AuthenticationAttempted", StringComparison.OrdinalIgnoreCase)),
        AuthenticationFailures = authenticationFailures.Count(),
        TodayAuthenticationFailures = authenticationFailures.Count(item => item.OccurredAtUtc >= dayStart && item.OccurredAtUtc < nextDayStart),
        ProtocolViolations = allEvents.Count(item => item.EventType.Equals("ProtocolViolation", StringComparison.OrdinalIgnoreCase)),
        SessionClosed = allEvents.Count(item => item.EventType.Equals("SessionClosed", StringComparison.OrdinalIgnoreCase)),
        ThreatIpCount = threats.GetAll().Count,
        ServiceInstanceCount = instances.GetAll().Count,
        ListenerCount = listeners.Count,
        RunningListenerCount = listeners.Count(item => item.State.Equals("Running", StringComparison.OrdinalIgnoreCase)),
        FailedListenerCount = listeners.Count(item => item.State.Equals("Failed", StringComparison.OrdinalIgnoreCase)),
        ActiveConnections = listeners.Sum(item => item.ActiveConnections),
        AcceptedCount = listeners.Sum(item => item.AcceptedCount),
        ListenerErrorCount = listeners.Sum(item => item.ErrorCount),
        EventsByAdapter = allEvents
            .GroupBy(item => string.IsNullOrWhiteSpace(item.AdapterKey) ? "unknown" : item.AdapterKey, StringComparer.OrdinalIgnoreCase)
            .Select(group => new MetricBucket(group.Key, group.LongCount()))
            .OrderByDescending(item => item.Count)
            .ToArray(),
        EventsByOutcome = allEvents
            .GroupBy(item => string.IsNullOrWhiteSpace(item.Outcome) ? "unknown" : item.Outcome, StringComparer.OrdinalIgnoreCase)
            .Select(group => new MetricBucket(group.Key, group.LongCount()))
            .OrderByDescending(item => item.Count)
            .ToArray(),
        EventsByHour = eventBuckets,
        AdapterActivity = adapterActivity,
        ActivityByHour = activityByHour,
        Listeners = listenerOverview,
        Host = HostOverviewReader.Read(now),
    };

    return Results.Ok(ApiResult<OverviewMetrics>.Ok(metrics));
});

app.MapHub<HoneypotHub>("/hubs/honeypot");
app.MapIPLocationEndpoints();
app.MapNotificationEndpoints();
app.MapSyslogEndpoints();

app.MapFallbackToFile("index.html");

app.Run();

public partial class Program;
