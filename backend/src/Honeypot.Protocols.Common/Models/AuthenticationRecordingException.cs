namespace Honeypot.Protocols.Common;

/// <summary>只携带固定错误码，避免存储异常中的凭据进入运行状态或日志。</summary>
public sealed class AuthenticationRecordingException(string code) : Exception(code)
{
    public string Code { get; } = code;
}
