namespace Honeypot.Shared.Models;

/// <summary>
/// 所有 HTTP 业务接口统一使用的返回包装，避免前后端各自解释错误结构。
/// </summary>
public sealed record ApiResult<T>(bool Success, string Code, string Message, T? Data)
{
    public static ApiResult<T> Ok(T data, string message = "success") =>
        new(true, "OK", message, data);

    public static ApiResult<T> Fail(string code, string message) =>
        new(false, code, message, default);
}
