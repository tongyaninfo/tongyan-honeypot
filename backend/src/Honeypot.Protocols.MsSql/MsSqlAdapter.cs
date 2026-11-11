using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Honeypot.Protocol.Abstractions.Models;
using Honeypot.Protocol.Abstractions.Service;
using Honeypot.Protocols.Common;
using Honeypot.Protocols.MsSql.Common;
using Honeypot.Protocols.MsSql.Models;

namespace Honeypot.Protocols.MsSql;

/// <summary>完成 TDS 7.x/TLS/LOGIN7/NTLM 到认证失败；绝不发送 LOGINACK 或执行 SQL。</summary>
public sealed class MsSqlAdapter : ProtocolAdapterBase
{
    public override ServiceAdapterDescriptor Descriptor => new()
    {
        AdapterKey = "mssql", DisplayName = "MSSQL", Version = "1",
        SupportedTransports = ["tcp"], SupportedFidelityLevels = ["L1", "L2", "L3"],
        SupportedClients = ["sqlcmd (TDS 7.x)", "Microsoft.Data.SqlClient (TDS 7.x)", "System.Data.SqlClient"],
    };

    public override async ValueTask HandleAsync(IHoneypotSession session, ProtocolSessionContext context,
        ServiceProfile profile, IInteractionEventSink sink, CancellationToken cancellationToken = default)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(profile.HandshakeTimeout);
        var ct = deadline.Token;
        var maximum = Math.Clamp(profile.MaxFrameBytes, 8, 131071);
        using var transport = new TdsSessionStream(session, profile.MaxSessionBytes);
        var closeReason = SessionCloseReason.AdapterCompleted;
        try
        {
            var (type, payload) = await TdsTransport.ReadMessageAsync(transport, maximum, ct);
            if (type != 0x12) throw new InvalidDataException("Expected PRELOGIN.");
            var requestedEncryption = TdsProtocol.ReadEncryption(payload);
            await sink.AppendAsync(Event(context, "HandshakeReceived", "handshake", "observed", "TDS 7.x PRELOGIN received", 1), ct);
            // 对可加密客户端要求完整 TLS，避免 login-only 加密切换和明文密码降级。
            // 只有显式 ENCRYPT_NOT_SUP 的旧客户端使用其本来声明的非 TLS 路径。
            var encryption = requestedEncryption == 2 ? (byte)2 : requestedEncryption == 0 ? (byte)3 : (byte)1;
            await TdsTransport.WriteMessageAsync(transport, 0x04, TdsProtocol.BuildPreLogin(encryption), ct);
            await sink.AppendAsync(Event(context, "PreLoginResponseSent", "handshake", "sent", $"tds encryption={encryption}"), ct);
            if (encryption == 2)
            {
                await HandleLoginAsync(transport, context, profile, sink, maximum, ct);
            }
            else
            {
                using var certificate = ProtocolTls.CreateServerCertificate(ProtocolFingerprint.HostName(profile));
                using var handshake = new TdsTlsHandshakeStream(transport, maximum);
                using var tls = new SslStream(handshake, leaveInnerStreamOpen: true);
                await tls.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
                {
                    ServerCertificate = certificate,
                    // TDS 7.x 在 PRELOGIN 后开始 TLS；TDS 8.0 的 TLS-first 不属于本实现。
                    EnabledSslProtocols = SslProtocols.Tls12,
                    ClientCertificateRequired = false,
                    CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                }, ct);
                handshake.CompleteHandshake();
                await sink.AppendAsync(Event(context, "TlsHandshakeCompleted", "tls", "observed", "TDS TLS established"), ct);
                await HandleLoginAsync(tls, context, profile, sink, maximum, ct);
            }
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            closeReason = SessionCloseReason.HandshakeTimeout;
            await sink.AppendAsync(Event(context, "HandshakeTimeout", "handshake", "failure", "TDS authentication deadline exceeded"), cancellationToken);
        }
        catch (OperationCanceledException)
        {
            closeReason = SessionCloseReason.ListenerStopping;
            throw;
        }
        catch (AuthenticationRecordingException)
        {
            closeReason = SessionCloseReason.StorageDegraded;
            throw;
        }
        catch (TdsResourceLimitException)
        {
            closeReason = SessionCloseReason.ResourceLimitExceeded;
            await sink.AppendAsync(Event(context, "ResourceLimitExceeded", "handshake", "failure", "TDS resource limit exceeded"), cancellationToken);
        }
        catch (EndOfStreamException) { closeReason = SessionCloseReason.ClientClosed; }
        catch (Exception ex) when (ex is InvalidDataException or DecoderFallbackException or AuthenticationException)
        {
            closeReason = SessionCloseReason.ProtocolViolation;
            // 不输出原始异常，避免协议载荷或认证材料进入日志。
            await sink.AppendAsync(Event(context, "ProtocolViolation", "handshake", "failure", "Invalid or unsupported TDS authentication exchange"), cancellationToken);
        }
        catch (IOException) { closeReason = SessionCloseReason.ClientClosed; }
        finally { await session.CloseAsync(closeReason, CancellationToken.None); }
    }

    private static async ValueTask HandleLoginAsync(Stream stream, ProtocolSessionContext context, ServiceProfile profile,
        IInteractionEventSink sink, int maximum, CancellationToken ct)
    {
        var (type, payload) = await TdsTransport.ReadMessageAsync(stream, maximum, ct);
        if (type != 0x10) throw new InvalidDataException("Expected LOGIN7.");
        var login = TdsProtocol.ReadLogin(payload);
        string? username = login.Username;
        if (login.IntegratedSecurity)
            username = await RecordSspiAsync(stream, login, context, profile, sink, maximum, ct);
        else
        {
            var material = login.FederatedAuthentication
                ? JsonSerializer.SerializeToUtf8Bytes(new { format = "tds-federated-v1", token = Convert.ToBase64String(payload) })
                : JsonSerializer.SerializeToUtf8Bytes(new
                {
                    format = "tds-sql-password-v1", username = login.Username, password = login.Password,
                    changePassword = login.ChangePassword, database = login.Database, hostname = login.HostName,
                    application = login.ApplicationName,
                });
            try
            {
                await RecordAuthenticationAsync(sink, context, profile, username,
                    login.FederatedAuthentication ? "federated" : "sql-password", "18456", 1,
                    login.FederatedAuthentication ? "Response" : "Plaintext", material, ct, database: login.Database);
            }
            finally { CryptographicOperations.ZeroMemory(material); }
        }
        await TdsTransport.WriteMessageAsync(stream, 0x04,
            TdsProtocol.BuildLoginError(username, ProtocolFingerprint.HostName(profile), login.Version), ct);
    }

    private static async ValueTask<string?> RecordSspiAsync(Stream stream, TdsLoginMessage login, ProtocolSessionContext context,
        ServiceProfile profile, IInteractionEventSink sink, int maximum, CancellationToken ct)
    {
        var initial = login.Sspi;
        var response = initial;
        byte[]? challenge = null;
        string? username = null;
        string? domain = null;
        string? workstation = null;
        var method = "sspi-unsupported";
        if (TdsSspi.TryReadNtlm(initial, out var negotiate, out var wrapped) && negotiate.Type == 1)
        {
            challenge = NtlmProtocol.BuildChallenge(ProtocolFingerprint.HostName(profile), negotiate.Flags);
            await TdsTransport.WriteMessageAsync(stream, 0x04, TdsSspi.BuildChallenge(challenge, wrapped), ct);
            await sink.AppendAsync(Event(context, "SspiChallengeSent", "authentication", "sent", "TDS NTLM challenge sent"), ct);
            var (type, token) = await TdsTransport.ReadMessageAsync(stream, maximum, ct);
            if (type != 0x11) throw new InvalidDataException("Expected SSPI response.");
            response = token;
            if (!TdsSspi.TryReadNtlm(response, out var authenticate, out _) || authenticate.Type != 3)
                throw new InvalidDataException("Invalid NTLM authenticate token.");
            username = authenticate.Username;
            domain = authenticate.Domain;
            workstation = authenticate.Workstation;
            method = "ntlm";
        }
        var material = JsonSerializer.SerializeToUtf8Bytes(new
        {
            format = "tds-sspi-v1", username, domain, workstation,
            negotiate = Convert.ToBase64String(initial), challenge = challenge is null ? null : Convert.ToBase64String(challenge),
            authenticate = Convert.ToBase64String(response),
        });
        try
        {
            await RecordAuthenticationAsync(sink, context, profile, username, method, "18456", 1, "Response", material, ct,
                domain: domain, database: login.Database);
        }
        finally { CryptographicOperations.ZeroMemory(material); }
        return username;
    }
}
