using System.Data.Common;
using Honeypot.Api.Common;
using Honeypot.Api.Models;
using Honeypot.Api.Service;
using Honeypot.Api.Service.impl;
using Honeypot.Shared.Models;
using Microsoft.EntityFrameworkCore;

namespace Honeypot.Api.Middleware;

/// <summary>关键管理操作先写审计预约，正常响应发出前记录结果，不依赖 Syslog。</summary>
public sealed class ManagementOperationAuditMiddleware(RequestDelegate next, ILogger<ManagementOperationAuditMiddleware> logger)
{
    private static readonly object ResourceIdKey = new();
    private static readonly object LockoutStartedKey = new();

    /// <summary>从已验证并实现的业务结果提取对象编号，不能直接传入未校验的路由值或正文。</summary>
    public static void SetResourceId(HttpContext context, string? resourceId)
    {
        if (resourceId is { Length: > 0 and <= 128 } && resourceId.All(character =>
            char.IsAsciiLetterOrDigit(character) || character is '-' or '_' or '.'))
            context.Items[ResourceIdKey] = resourceId;
    }

    public static void MarkLoginLockoutStarted(HttpContext context) => context.Items[LockoutStartedKey] = true;

    public async Task InvokeAsync(HttpContext context, ManagementOperationAuditStore store)
    {
        var operation = ManagementOperationCatalog.Find((context.GetEndpoint() as RouteEndpoint)?.RoutePattern.RawText,
            context.Request.Method.ToUpperInvariant());
        if (operation is null)
        {
            await next(context);
            return;
        }

        if (operation is ManagementOperationCatalog.Login or ManagementOperationCatalog.Logout)
        {
            // 先执行现有鉴权和登录锁定，再记录有效操作。锁定期间的重复 429 请求或无会话退出不会刷库。
            context.Response.OnStarting(() => RecordPublicOperationAsync(context, store, operation));
            await next(context);
            return;
        }

        if (operation == ManagementOperationCatalog.Initialize)
        {
            // 只给尚未完成初始化的请求注册结果审计。匿名失败不会占用后续成功初始化的额度。
            if (!context.RequestServices.GetRequiredService<IUserIdentityService>().IsInitialized)
                context.Response.OnStarting(() => RecordPublicOperationAsync(context, store, operation));
            await next(context);
            return;
        }

        string id;
        try { id = await store.BeginAsync(operation, ActorId(context), context.RequestAborted); }
        catch (Exception error) when (error is DbException or DbUpdateException)
        {
            logger.LogWarning("Management operation audit could not reserve a record. Operation={Operation}", operation);
            context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
            context.Response.Headers.CacheControl = "no-store";
            await context.Response.WriteAsJsonAsync(ApiResult<object>.Fail("MANAGEMENT_AUDIT_UNAVAILABLE", "管理操作审计暂不可用，请稍后重试。"),
                context.RequestAborted);
            return;
        }

        var completed = false;
        context.Response.OnStarting(() => CompleteAsync(context.Response.StatusCode));
        try { await next(context); }
        catch (OperationCanceledException) when (context.RequestAborted.IsCancellationRequested)
        {
            // 客户端中断时业务结果可能不明，保留预约记录，由查询标记 Unknown。
            completed = true;
            throw;
        }
        catch
        {
            await CompleteAsync(StatusCodes.Status500InternalServerError);
            throw;
        }

        async Task CompleteAsync(int status)
        {
            if (completed) return;
            completed = true;
            try { await store.CompleteAsync(id, ActorId(context), context.Items[ResourceIdKey] as string, status, CancellationToken.None); }
            catch (Exception error) when (error is DbException or DbUpdateException)
            {
                // 操作可能已经提交。保留预约记录及服务端诊断，避免向客户端报告可重试的业务失败。
                logger.LogWarning("Management operation audit could not record the outcome. Operation={Operation} AuditId={AuditId}",
                    operation, id);
            }
        }
    }

    private async Task RecordPublicOperationAsync(HttpContext context, ManagementOperationAuditStore store, string operation)
    {
        var actorId = ActorId(context);
        var status = context.Response.StatusCode;
        var succeeded = status is >= 200 and < 300;
        var verifiedSession = actorId is not null && succeeded;
        var shouldRecord = operation switch
        {
            ManagementOperationCatalog.Initialize => succeeded || status >= 400,
            ManagementOperationCatalog.Login => verifiedSession || status >= 400,
            ManagementOperationCatalog.Logout => verifiedSession,
            _ => false,
        };
        if (!shouldRecord) return;

        try
        {
            var resourceId = succeeded && operation == ManagementOperationCatalog.Initialize
                ? context.Items[ResourceIdKey] as string : null;
            await store.RecordCompletedAsync(operation, succeeded ? actorId : null,
                resourceId, status, CancellationToken.None);
        }
        catch (Exception error) when (error is DbException or DbUpdateException)
        {
            // 身份文件与审计库不共事务。审计故障不改写已执行的初始化和认证结果。
            logger.LogWarning("Public management operation audit could not be saved. Operation={Operation}", operation);
        }
    }

    private static string? ActorId(HttpContext context) => (context.Items["CurrentUser"] as AuthenticatedUser)?.UserId;
}
