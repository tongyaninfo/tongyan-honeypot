using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text.Json;
using Honeypot.Protocol.Abstractions.Models;
using Honeypot.Protocol.Abstractions.Service;
using Honeypot.Protocols.Common;
using Honeypot.Protocols.Smb.Common;

namespace Honeypot.Protocols.Smb;

/// <summary>SMB2/3 只完成安全协商与认证拒绝，永不建立共享、Guest 或文件会话。</summary>
public sealed class SmbAdapter : ProtocolAdapterBase
{
    private readonly byte[] _serverGuid = Guid.NewGuid().ToByteArray();
    private readonly DateTimeOffset _startedAt = DateTimeOffset.UtcNow;
    public override ServiceAdapterDescriptor Descriptor => new()
    {
        AdapterKey = "smb", DisplayName = "SMB", SupportedTransports = ["tcp"],
        SupportedFidelityLevels = ["L1", "L2", "L3"], SupportedClients = ["SMB2/3 NTLM clients"],
    };

    public override async ValueTask HandleAsync(IHoneypotSession session, ProtocolSessionContext context,
        ServiceProfile profile, IInteractionEventSink sink, CancellationToken cancellationToken = default)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(profile.HandshakeTimeout);
        var ct = deadline.Token;
        var closeReason = SessionCloseReason.AdapterCompleted;
        long consumed = 0;
        async ValueTask<byte[]> Read()
        {
            var header = new byte[4];
            if (!await ReadExactAsync(session, header, ct)) throw new EndOfStreamException();
            var length = BinaryPrimitives.ReadUInt32BigEndian(header);
            // Direct TCP framing 的首字节必须为 0，不接受 NetBIOS session request 或 SMB 压缩帧。
            if (length < 64 || length > profile.MaxFrameBytes) throw new InvalidDataException("Invalid SMB frame length.");
            consumed += 4 + length;
            if (consumed > profile.MaxSessionBytes) throw new SmbBudgetException();
            var packet = new byte[(int)length];
            if (!await ReadExactAsync(session, packet, ct)) throw new EndOfStreamException();
            return packet;
        }
        async ValueTask Write(byte[] packet)
        {
            consumed += 4 + packet.Length;
            if (consumed > profile.MaxSessionBytes) throw new SmbBudgetException();
            var frame = new byte[4 + packet.Length];
            BinaryPrimitives.WriteUInt32BigEndian(frame, (uint)packet.Length); packet.CopyTo(frame, 4);
            await session.WriteAsync(frame, ct);
        }
        try
        {
            var request = await Read();
            if (SmbProtocol.Command(request) != 0) throw new InvalidDataException("Expected SMB negotiate.");
            var dialect = SmbProtocol.SelectDialect(request);
            var preauth = dialect == 0x0311 ? SmbProtocol.Hash(new byte[64], request) : [];
            var response = SmbProtocol.NegotiateResponse(request, dialect, _serverGuid, _startedAt, profile.MaxFrameBytes);
            if (dialect == 0x0311) preauth = SmbProtocol.Hash(preauth, response);
            await Write(response);
            await sink.AppendAsync(Event(context, "HandshakeReceived", "handshake", "observed", $"SMB dialect 0x{dialect:X4} negotiated", 1), ct);
            request = await Read();
            if (SmbProtocol.Command(request) != 1 || SmbProtocol.U64(request, 40) != 0)
                throw new InvalidDataException("Expected new SMB session setup.");
            if (dialect == 0x0311) preauth = SmbProtocol.Hash(preauth, request);
            var initial = SmbProtocol.SecurityToken(request);
            var token = initial;
            var sessionId = BinaryPrimitives.ReadUInt64LittleEndian(RandomNumberGenerator.GetBytes(8)) | 1UL;
            byte[]? challenge = null;
            string? username = null, domain = null, workstation = null;
            var method = "SMB/SPNEGO";
            if (SmbSpnego.TryNtlm(initial, out var negotiate, out var wrapped))
            {
                if (negotiate.Type != 1) throw new InvalidDataException("Expected NTLM negotiate.");
                challenge = NtlmProtocol.BuildChallenge(ProtocolFingerprint.HostName(profile), negotiate.Flags);
                response = SmbProtocol.SessionChallenge(request, SmbSpnego.Challenge(challenge, wrapped), sessionId);
                if (dialect == 0x0311) preauth = SmbProtocol.Hash(preauth, response);
                await Write(response);
                request = await Read();
                if (SmbProtocol.Command(request) != 1 || SmbProtocol.U64(request, 40) != sessionId)
                    throw new InvalidDataException("Invalid SMB authentication session.");
                if (dialect == 0x0311) preauth = SmbProtocol.Hash(preauth, request);
                token = SmbProtocol.SecurityToken(request);
                if (!SmbSpnego.TryNtlm(token, out var authenticate, out _) || authenticate.Type != 3)
                    throw new InvalidDataException("Invalid SMB NTLM authenticate.");
                username = authenticate.Username; domain = authenticate.Domain; workstation = authenticate.Workstation;
                method = "SMB/NTLM";
            }
            else if (!SmbSpnego.IsOtherAuthenticationToken(initial))
                throw new InvalidDataException("Malformed SMB security token.");
            var material = JsonSerializer.SerializeToUtf8Bytes(new
            {
                format = "smb-authentication-v1", username, domain, workstation, dialect = $"0x{dialect:X4}",
                negotiate = Convert.ToBase64String(initial), challenge = challenge is null ? null : Convert.ToBase64String(challenge),
                authenticate = Convert.ToBase64String(token), preauthenticationHash = preauth.Length == 0 ? null : Convert.ToBase64String(preauth),
            });
            try
            {
                await RecordAuthenticationAsync(sink, context, profile, username, method, "STATUS_LOGON_FAILURE", 1,
                    "Response", material, ct, domain: domain);
            }
            finally { CryptographicOperations.ZeroMemory(material); }
            await Write(SmbProtocol.Error(request, SmbProtocol.LogonFailure, sessionId));
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            closeReason = SessionCloseReason.HandshakeTimeout;
            await sink.AppendAsync(Event(context, "HandshakeTimeout", "handshake", "failure", "SMB authentication deadline exceeded"), cancellationToken);
        }
        catch (AuthenticationRecordingException) { closeReason = SessionCloseReason.StorageDegraded; throw; }
        catch (SmbBudgetException)
        {
            closeReason = SessionCloseReason.ResourceLimitExceeded;
            await sink.AppendAsync(Event(context, "ResourceLimitExceeded", "handshake", "failure", "SMB session budget exceeded"), cancellationToken);
        }
        catch (InvalidDataException)
        {
            closeReason = SessionCloseReason.ProtocolViolation;
            await sink.AppendAsync(Event(context, "ProtocolViolation", "handshake", "failure", "Invalid SMB authentication exchange"), cancellationToken);
        }
        catch (IOException) { closeReason = SessionCloseReason.ClientClosed; }
        catch (OperationCanceledException) { closeReason = SessionCloseReason.ListenerStopping; throw; }
        finally { await session.CloseAsync(closeReason, CancellationToken.None); }
    }

    private sealed class SmbBudgetException : Exception;
}
