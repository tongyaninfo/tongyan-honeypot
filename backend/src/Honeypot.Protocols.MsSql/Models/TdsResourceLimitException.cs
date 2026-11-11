namespace Honeypot.Protocols.MsSql.Models;

/// <summary>固定资源超限诊断，不携带原始报文或凭据。</summary>
internal sealed class TdsResourceLimitException : IOException
{
    public TdsResourceLimitException() : base("TDS resource limit exceeded.") { }
}
