using System.Buffers.Binary;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Honeypot.Protocol.Abstractions.Models;
using Honeypot.Protocol.Abstractions.Service;
using Honeypot.Protocols.Common;

namespace Honeypot.Protocols.Rdp;

/// <summary>有界 X.224/TLS/CredSSP 认证服务；认证永远失败，不创建桌面或成功后的凭据委派。</summary>
public sealed class RdpAdapter : ProtocolAdapterBase
{
    public override ServiceAdapterDescriptor Descriptor => new()
    {
        AdapterKey = "rdp", DisplayName = "RDP", Version = "1",
        SupportedTransports = ["tcp"], SupportedFidelityLevels = ["L1", "L2", "L3"],
        SupportedClients = ["mstsc", "xfreerdp", "rdp-probe"],
    };

    public override async ValueTask HandleAsync(IHoneypotSession session, ProtocolSessionContext context,
        ServiceProfile profile, IInteractionEventSink sink, CancellationToken ct = default)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(profile.HandshakeTimeout);
        var token = deadline.Token;
        var closeReason = SessionCloseReason.AdapterCompleted;
        try
        {
            var first = await ReadFrameAsync(session, Math.Min(profile.MaxFrameBytes, 4096), 4,
                header => BinaryPrimitives.ReadUInt16BigEndian(header.AsSpan(2)), token);
            if (first is null) return;
            if (!TryReadNegotiation(first, out var requested))
            {
                closeReason = SessionCloseReason.ProtocolViolation;
                await sink.AppendAsync(Event(context, "ProtocolViolation", "x224", "malformed", "Invalid X.224 connection request"), token);
                return;
            }
            await sink.AppendAsync(Event(context, "HandshakeReceived", "x224", "observed", $"requestedProtocols={requested}"), token);
            var selected = (requested & 2) != 0 ? 2u : (requested & 8) != 0 ? 8u : 0u;
            if (selected == 0)
            {
                closeReason = SessionCloseReason.ProtocolViolation;
                // 没有 NLA 的客户端合法拒绝，不谎称已经收到了账号或密码。
                await session.WriteAsync(NegotiationResponse(3, 5), token);
                await sink.AppendAsync(Event(context, "ProtocolViolation", "x224", "unsupported", "HYBRID_REQUIRED_BY_SERVER"), token);
                return;
            }
            await session.WriteAsync(NegotiationResponse(2, selected), token);
            await sink.AppendAsync(Event(context, "X224ConnectionConfirmSent", "handshake", "sent", $"selectedProtocol={selected}"), token);
            if (session is not IRawStreamHoneypotSession raw)
            {
                closeReason = SessionCloseReason.InternalError;
                await sink.AppendAsync(Event(context, "ProtocolViolation", "tls", "unsupported", "TLS stream is unavailable"), token);
                return;
            }
            using var certificate = ProtocolTls.CreateServerCertificate(ProtocolFingerprint.HostName(profile));
            using var tls = new SslStream(raw.RawStream, leaveInnerStreamOpen: true);
            await tls.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
            {
                ServerCertificate = certificate,
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                ClientCertificateRequired = false,
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
            }, token);
            await sink.AppendAsync(Event(context, "TlsHandshakeCompleted", "tls", "observed", "RDP TLS handshake completed"), token);
            await HandleCredSspAsync(tls, context, profile, sink, token);
        }
        catch (AuthenticationRecordingException) { closeReason = SessionCloseReason.StorageDegraded; throw; }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            closeReason = SessionCloseReason.HandshakeTimeout;
            await sink.AppendAsync(Event(context, "ProtocolViolation", "handshake", "timeout", "RDP authentication timed out"), ct);
        }
        catch (Exception ex) when (ex is AuthenticationException or InvalidDataException or OverflowException)
        {
            closeReason = SessionCloseReason.ProtocolViolation;
            // 不输出包含原始报文的异常信息。
            await sink.AppendAsync(Event(context, "ProtocolViolation", "handshake", "malformed", "RDP handshake or authentication packet rejected"), ct);
        }
        catch (OperationCanceledException) { closeReason = SessionCloseReason.ListenerStopping; throw; }
        catch (IOException) { closeReason = SessionCloseReason.ClientClosed; }
        catch (Exception) { closeReason = SessionCloseReason.InternalError; throw; }
        finally
        {
            await session.CloseAsync(closeReason, CancellationToken.None);
        }
    }

    private static async Task HandleCredSspAsync(Stream tls, ProtocolSessionContext context, ServiceProfile profile,
        IInteractionEventSink sink, CancellationToken ct)
    {
        byte[]? challenge = null;
        byte[]? negotiate = null;
        int? negotiatedVersion = null;
        for (var round = 0; round < 2; round++)
        {
            var bytes = await ReadDerMessageAsync(tls, Math.Min(profile.MaxFrameBytes, 65536), ct);
            if (bytes is null) return;
            if (!CredSspProtocol.TryReadRequest(bytes, out var request) ||
                (negotiatedVersion.HasValue && request.Version != negotiatedVersion.Value))
                throw new InvalidDataException();
            negotiatedVersion ??= request.Version;
            var version = negotiatedVersion.Value;
            if (request.NegoToken is null || !CredSspProtocol.TryExtractNtlmMechanism(request.NegoToken, out var token) ||
                !NtlmProtocol.TryParse(token, out var ntlm))
            {
                await RecordAuthenticationAsync(sink, context, profile, null, "CredSSP/SPNEGO", "STATUS_LOGON_FAILURE", 1,
                    "Response", JsonSerializer.SerializeToUtf8Bytes(new { credSspVersion = version, request = Convert.ToBase64String(bytes) }), ct);
                await tls.WriteAsync(CredSspProtocol.BuildAuthenticationFailure(version), ct);
                return;
            }
            if (ntlm.Type == 1 && challenge is null)
            {
                var useSpnego = !request.NegoToken.AsSpan().StartsWith("NTLMSSP\0"u8);
                negotiate = token;
                challenge = NtlmProtocol.BuildChallenge(ProtocolFingerprint.HostName(profile), ntlm.Flags);
                await tls.WriteAsync(CredSspProtocol.BuildChallenge(challenge, version, useSpnego), ct);
                await sink.AppendAsync(Event(context, "CredSspChallengeSent", "credssp", "sent", "NTLM Type 2 challenge sent"), ct);
                continue;
            }
            // MS-SPNG 允许 Windows 在 NTLM 协商后直接提交带 MIC 的 Type3，不能强制其仍有 SPNEGO 外壳。
            if (ntlm.Type != 3 || challenge is null) throw new InvalidDataException();
            var evidence = JsonSerializer.SerializeToUtf8Bytes(new
            {
                username = ntlm.Username, domain = ntlm.Domain, workstation = ntlm.Workstation,
                method = "NTLM", credSspVersion = version,
                negotiate = Convert.ToBase64String(negotiate!), challenge = Convert.ToBase64String(challenge),
                authenticate = Convert.ToBase64String(token), request = Convert.ToBase64String(bytes),
            });
            await RecordAuthenticationAsync(sink, context, profile, ntlm.Username, "CredSSP/NTLM", "STATUS_LOGON_FAILURE", 1,
                "Response", evidence, ct, domain: ntlm.Domain);
            await tls.WriteAsync(CredSspProtocol.BuildAuthenticationFailure(version), ct);
            await tls.FlushAsync(ct);
            return;
        }
        throw new InvalidDataException();
    }

    internal static bool TryReadNegotiation(ReadOnlySpan<byte> bytes, out uint requested)
    {
        requested = 0;
        if (bytes.Length < 11 || bytes[0] != 3 || bytes[1] != 0 ||
            BinaryPrimitives.ReadUInt16BigEndian(bytes[2..]) != bytes.Length || bytes[4] != bytes.Length - 5 ||
            bytes[5] != 0xE0 || bytes[10] != 0) return false;
        var offset = 11;
        if (bytes[offset..].StartsWith("Cookie: "u8))
        {
            var end = bytes[offset..].IndexOf("\r\n"u8);
            if (end < 0) return false;
            offset += end + 2;
        }
        if (offset == bytes.Length) return true;
        if (bytes.Length - offset < 8 || bytes[offset] != 1 ||
            BinaryPrimitives.ReadUInt16LittleEndian(bytes[(offset + 2)..]) != 8) return false;
        requested = BinaryPrimitives.ReadUInt32LittleEndian(bytes[(offset + 4)..]);
        var correlationPresent = (bytes[offset + 1] & 8) != 0;
        offset += 8;
        if (correlationPresent)
        {
            if (bytes.Length - offset != 36 || bytes[offset] != 6 || BinaryPrimitives.ReadUInt16LittleEndian(bytes[(offset + 2)..]) != 36) return false;
            offset += 36;
        }
        return offset == bytes.Length;
    }

    private static byte[] NegotiationResponse(byte type, uint value)
    {
        byte[] bytes = [3, 0, 0, 19, 14, 0xD0, 0, 0, 0x12, 0x34, 0, type, 0, 8, 0, 0, 0, 0, 0];
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(15), value);
        return bytes;
    }

    private static async ValueTask<byte[]?> ReadDerMessageAsync(Stream stream, int maxBytes, CancellationToken ct)
    {
        var header = new byte[2];
        if (await stream.ReadAsync(header.AsMemory(0, 1), ct) == 0) return null;
        await stream.ReadExactlyAsync(header.AsMemory(1), ct);
        if (header[0] != 0x30) throw new InvalidDataException();
        var length = (uint)header[1];
        byte[] encoded = [];
        if ((length & 0x80) != 0)
        {
            var count = (int)(length & 0x7F);
            if (count is 0 or > 4) throw new InvalidDataException();
            encoded = new byte[count];
            await stream.ReadExactlyAsync(encoded, ct);
            if (encoded[0] == 0) throw new InvalidDataException();
            length = 0;
            foreach (var part in encoded) length = (length << 8) | part;
            if (length < 128) throw new InvalidDataException();
        }
        if (length > maxBytes - 2 - encoded.Length) throw new InvalidDataException();
        var result = new byte[2 + encoded.Length + (int)length];
        header.CopyTo(result, 0);
        encoded.CopyTo(result, 2);
        await stream.ReadExactlyAsync(result.AsMemory(2 + encoded.Length), ct);
        return result;
    }
}
