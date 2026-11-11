using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Honeypot.Protocol.Abstractions.Models;
using Honeypot.Protocol.Abstractions.Service;
using Honeypot.Protocols.Common;
using Honeypot.Protocols.Nfs.Common;

namespace Honeypot.Protocols.Nfs;

/// <summary>NFSv4.1 原生 RPC 观测：AUTH_SYS 不包含密码，只记录声明的身份并拒绝目录访问。</summary>
public sealed class NfsAdapter : ProtocolAdapterBase
{
    public override ServiceAdapterDescriptor Descriptor => new()
    {
        AdapterKey = "nfs", DisplayName = "NFS", SupportedTransports = ["tcp"],
        SupportedFidelityLevels = ["L1", "L2", "L3"], SupportedClients = ["NFSv4.1 AUTH_SYS clients"],
    };

    public override async ValueTask HandleAsync(IHoneypotSession session, ProtocolSessionContext context,
        ServiceProfile profile, IInteractionEventSink sink, CancellationToken cancellationToken = default)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(profile.HandshakeTimeout);
        var ct = deadline.Token;
        var closeReason = SessionCloseReason.AdapterCompleted;
        var compound = new NfsCompound(ProtocolFingerprint.HostName(profile), profile.MaxFrameBytes);
        long consumed = 0;
        try
        {
            // RPC NULL 与协议协商不产生认证事件；同一会话总请求数量也有独立上限。
            for (var requestIndex = 0; requestIndex < 32; requestIndex++)
            {
                using var payload = new MemoryStream();
                for (var fragmentIndex = 0; ; fragmentIndex++)
                {
                    if (fragmentIndex >= 128) throw new NfsBudgetException();
                    var header = new byte[4];
                    if (!await ReadExactAsync(session, header, ct)) throw new EndOfStreamException();
                    var marker = BinaryPrimitives.ReadUInt32BigEndian(header);
                    var length = marker & 0x7FFFFFFF;
                    if (length == 0 || length > profile.MaxFrameBytes || payload.Length + length > profile.MaxFrameBytes)
                        throw new InvalidDataException("Invalid RPC record length.");
                    consumed += 4 + length;
                    if (consumed > profile.MaxSessionBytes) throw new NfsBudgetException();
                    var fragment = new byte[(int)length];
                    if (!await ReadExactAsync(session, fragment, ct)) throw new EndOfStreamException();
                    payload.Write(fragment);
                    if ((marker & 0x80000000) != 0) break;
                }
                var request = payload.ToArray();
                var reader = new XdrReader(request);
                var xid = reader.UInt();
                if (reader.UInt() != 0) throw new InvalidDataException("Expected RPC CALL.");
                byte[] response;
                var complete = false;
                if (reader.UInt() != 2)
                {
                    var rejected = new XdrWriter(); rejected.UInt(xid); rejected.UInt(1); rejected.UInt(1); rejected.UInt(0);
                    rejected.UInt(2); rejected.UInt(2); response = rejected.Bytes(); complete = true;
                }
                else
                {
                    var program = reader.UInt(); var version = reader.UInt(); var procedure = reader.UInt();
                    var flavor = reader.UInt(); var credential = reader.Opaque(400); reader.UInt(); reader.Opaque(400);
                    if (program != 100003) response = Accepted(xid, 1);
                    else if (version != 4)
                    {
                        var versions = new XdrWriter(); versions.UInt(4); versions.UInt(4);
                        response = Accepted(xid, 2, versions.Bytes());
                    }
                    else if (procedure == 0) { reader.End(); response = Accepted(xid, 0); }
                    else if (procedure != 1) response = Accepted(xid, 3);
                    else if (flavor != 1)
                    {
                        // 无有效 KDC/服务密钥时明确拒绝 GSS，不声称已验证票据或获得用户密码。
                        var method = flavor == 6 ? "RPCSEC_GSS" : flavor == 0 ? "AUTH_NONE" : $"RPC_AUTH_{flavor}";
                        var failure = flavor == 6 ? "RPCSEC_GSS_CREDPROBLEM" : "AUTH_TOOWEAK";
                        var args = reader.Fixed(reader.Remaining);
                        var material = JsonSerializer.SerializeToUtf8Bytes(new
                        {
                            format = "nfs-rpc-auth-v1", flavor, credential = Convert.ToBase64String(credential), request = Convert.ToBase64String(args),
                        });
                        try { await RecordDenied(sink, context, profile, null, method, failure, flavor == 6 ? "Response" : "Identity", material, ct); }
                        finally { CryptographicOperations.ZeroMemory(material); }
                        var rejected = new XdrWriter(); rejected.UInt(xid); rejected.UInt(1); rejected.UInt(1); rejected.UInt(1);
                        rejected.UInt(flavor == 6 ? 13u : 5u); response = rejected.Bytes(); complete = true;
                    }
                    else
                    {
                        var identity = ReadIdentity(credential);
                        var args = reader.Fixed(reader.Remaining);
                        var result = compound.Process(args);
                        if (result.AccessDenied)
                        {
                            var material = JsonSerializer.SerializeToUtf8Bytes(new
                            {
                                format = "nfs-auth-sys-v1", identity.Host, identity.Uid, identity.Gid, identity.Groups,
                                identityVerified = false, operation = result.Operation, path = result.Path,
                            });
                            try
                            {
                                await RecordDenied(sink, context, profile, $"uid:{identity.Uid}", "AUTH_SYS", "NFS4ERR_ACCESS", "Identity", material, ct);
                            }
                            finally { CryptographicOperations.ZeroMemory(material); }
                            complete = true;
                        }
                        response = Accepted(xid, 0, result.Body);
                    }
                }
                consumed += response.Length + 4;
                if (consumed > profile.MaxSessionBytes) throw new NfsBudgetException();
                var frame = new byte[response.Length + 4];
                BinaryPrimitives.WriteUInt32BigEndian(frame, (uint)response.Length | 0x80000000); response.CopyTo(frame, 4);
                await session.WriteAsync(frame, ct);
                if (complete) return;
            }
            throw new NfsBudgetException();
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            closeReason = SessionCloseReason.HandshakeTimeout;
            await sink.AppendAsync(Event(context, "HandshakeTimeout", "handshake", "failure", "NFS negotiation deadline exceeded"), cancellationToken);
        }
        catch (AuthenticationRecordingException) { closeReason = SessionCloseReason.StorageDegraded; throw; }
        catch (NfsBudgetException)
        {
            closeReason = SessionCloseReason.ResourceLimitExceeded;
            await sink.AppendAsync(Event(context, "ResourceLimitExceeded", "handshake", "failure", "NFS session budget exceeded"), cancellationToken);
        }
        catch (Exception ex) when (ex is InvalidDataException or DecoderFallbackException)
        {
            closeReason = SessionCloseReason.ProtocolViolation;
            await sink.AppendAsync(Event(context, "ProtocolViolation", "handshake", "failure", "Invalid NFS RPC/XDR exchange"), cancellationToken);
        }
        catch (IOException) { closeReason = SessionCloseReason.ClientClosed; }
        catch (OperationCanceledException) { closeReason = SessionCloseReason.ListenerStopping; throw; }
        finally { await session.CloseAsync(closeReason, CancellationToken.None); }
    }

    private static (string Host, uint Uid, uint Gid, uint[] Groups) ReadIdentity(byte[] credential)
    {
        var reader = new XdrReader(credential); reader.UInt(); var host = reader.Text(255);
        var uid = reader.UInt(); var gid = reader.UInt(); var groups = reader.Array(16); reader.End();
        return (host, uid, gid, groups);
    }

    private static byte[] Accepted(uint xid, uint status, byte[]? body = null)
    {
        var writer = new XdrWriter(); writer.UInt(xid); writer.UInt(1); writer.UInt(0); writer.UInt(0); writer.UInt(0); writer.UInt(status);
        if (body is not null) writer.Fixed(body); return writer.Bytes();
    }

    private static async ValueTask RecordDenied(IInteractionEventSink sink, ProtocolSessionContext context, ServiceProfile profile,
        string? identity, string method, string failure, string type, byte[] material, CancellationToken ct)
    {
        var access = Event(context, "AuthorizationDenied", "authorization", "failure", "NFS access rejected", 3,
            username: profile.RecordUsername ? identity : null) with
        {
            AuthenticationMethod = method, AuthenticationFailureCode = failure, MaterialType = type, CredentialCaptureStatus = "Disabled",
        };
        var stage = "CredentialCaptureFailed";
        try
        {
            if (profile.StoreCredentialEvidence && profile.RecordPassword)
            {
                var artifact = await StoreAsync(sink, context, access.EventId, type, material, profile, ct);
                access = access with { CredentialArtifactId = artifact, CredentialCaptureStatus = "Captured" };
            }
            stage = "AuthenticationEventWriteFailed";
            if (!(await sink.AppendAsync(access, ct)).Recorded) throw new AuthenticationRecordingException(stage);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception)
        {
            try { await sink.AppendAsync(Event(context, stage, "authorization", "storage_failed", "NFS evidence could not be recorded"), ct); }
            catch (Exception) { /* 不将证据内容或存储异常传播到日志。 */ }
            throw new AuthenticationRecordingException(stage);
        }
    }
    private sealed class NfsBudgetException : Exception;
}
