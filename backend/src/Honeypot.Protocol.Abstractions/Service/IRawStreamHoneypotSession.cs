namespace Honeypot.Protocol.Abstractions.Service;

/// <summary>
/// 为需要升级到 TLS 的协议适配器提供底层 TCP 流。
/// 普通适配器仍只使用 IHoneypotSession 的受控读写接口。
/// </summary>
public interface IRawStreamHoneypotSession
{
    Stream RawStream { get; }
}
