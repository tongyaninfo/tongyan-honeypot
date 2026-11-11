using System.Buffers;
using System.Buffers.Binary;
using System.Formats.Asn1;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Honeypot.Protocol.Abstractions.Models;
using Honeypot.Protocols.Common;
using Honeypot.Protocols.Rdp;
using Xunit;

namespace Honeypot.Protocols.Tests;

public sealed class RdpAuthenticationTests
{
    [Theory]
    [InlineData(2, "Negotiate", false)]
    [InlineData(3, "NTLM", false)]
    [InlineData(4, "NTLM", false)]
    [InlineData(5, "Negotiate", false)]
    [InlineData(6, "NTLM", false)]
    [InlineData(6, "Negotiate", false)]
    [InlineData(6, "Negotiate", true)]
    public async Task FullNlaExchangeRecordsChallengeAndIdentityBeforeLogonFailure(int version, string package,
        bool sendRawAuthenticate)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(12));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var sink = new SshAuthenticationTests.EvidenceSink();
        var server = RunServer(listener, sink, timeout.Token);
        using var client = new TcpClient();
        await client.ConnectAsync((IPEndPoint)listener.LocalEndpoint, timeout.Token);
        await using var stream = client.GetStream();
        await stream.WriteAsync(NegotiationRequest(3), timeout.Token);
        var confirm = new byte[19];
        await stream.ReadExactlyAsync(confirm, timeout.Token);
        Assert.Equal(2u, BinaryPrimitives.ReadUInt32LittleEndian(confirm.AsSpan(15)));
        using var tls = new SslStream(stream, true);
        await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
        {
            TargetHost = "rdp-authentication-test", EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
            RemoteCertificateValidationCallback = (_, _, _, _) => true,
        }, timeout.Token);
        using var authentication = new NegotiateAuthentication(new NegotiateAuthenticationClientOptions
        {
            Package = package, Credential = new NetworkCredential("取证-user", "rdp-isolated-sample", "TEST-DOMAIN"),
            TargetName = "TERMSRV/rdp-authentication-test", RequiredProtectionLevel = ProtectionLevel.EncryptAndSign,
        });
        var negotiate = authentication.GetOutgoingBlob(ReadOnlySpan<byte>.Empty, out var status)!;
        Assert.Equal(NegotiateAuthenticationStatusCode.ContinueNeeded, status);
        Assert.Equal(package == "NTLM", negotiate.AsSpan().StartsWith("NTLMSSP\0"u8));
        // 认证报文由 .NET 的独立 NTLM/SPNEGO 实现生成，TSRequest 按规范封装。
        var nonce = RandomNumberGenerator.GetBytes(32);
        await tls.WriteAsync(Request(negotiate, version, nonce: version >= 5 ? nonce : null), timeout.Token);
        var challengeMessage = await ReadDerAsync(tls, timeout.Token);
        Assert.True(CredSspProtocol.TryExtractNtlmToken(challengeMessage, out var challenge));
        Assert.Equal(2u, BinaryPrimitives.ReadUInt32LittleEndian(challenge.AsSpan(8)));
        Assert.NotEqual(new byte[8], challenge.AsSpan(24, 8).ToArray());
        var avOffset = (int)BinaryPrimitives.ReadUInt32LittleEndian(challenge.AsSpan(44));
        var avLength = BinaryPrimitives.ReadUInt16LittleEndian(challenge.AsSpan(40));
        var ids = new List<ushort>();
        for (var offset = avOffset; offset < avOffset + avLength;)
        {
            var id = BinaryPrimitives.ReadUInt16LittleEndian(challenge.AsSpan(offset));
            var length = BinaryPrimitives.ReadUInt16LittleEndian(challenge.AsSpan(offset + 2));
            ids.Add(id); offset += 4 + length;
        }
        Assert.Contains((ushort)1, ids); Assert.Contains((ushort)2, ids); Assert.Contains((ushort)7, ids);
        // 只能剥离 TSRequest；不能像旧测试一样先从错误的 SPNEGO 包装里找出 NTLM。
        var challengeToken = ReadNegoToken(challengeMessage);
        Assert.Equal(package == "NTLM", challengeToken.AsSpan().StartsWith("NTLMSSP\0"u8));
        var authenticateToken = authentication.GetOutgoingBlob(challengeToken, out status)!;
        Assert.Contains(status, new[] { NegotiateAuthenticationStatusCode.Completed, NegotiateAuthenticationStatusCode.ContinueNeeded });
        Assert.NotEmpty(authenticateToken);
        Assert.True(CredSspProtocol.TryExtractNtlmMechanism(authenticateToken, out var authenticate));
        var binding = version >= 5
            ? SHA256.HashData(Encoding.ASCII.GetBytes("CredSSP Client-To-Server Binding Hash\0")
                .Concat(nonce).Concat(tls.RemoteCertificate!.GetPublicKey()).ToArray())
            : tls.RemoteCertificate!.GetPublicKey();
        var protectedBinding = new ArrayBufferWriter<byte>();
        Assert.Equal(NegotiateAuthenticationStatusCode.Completed,
            authentication.Wrap(binding, protectedBinding, true, out var encrypted));
        Assert.True(encrypted);
        // 分片写入验证 DER/TLS 收包没有假设一次 Read 取得整个认证报文。
        // Windows 可在 SPNEGO 协商后直接发送带 MIC 的 Type3（MS-SPNG Appendix A）。
        var request = Request(sendRawAuthenticate ? authenticate : authenticateToken, version,
            protectedBinding.WrittenSpan.ToArray(), version >= 5 ? nonce : null);
        foreach (var value in request) await tls.WriteAsync(new[] { value }, timeout.Token);
        var failure = await ReadDerAsync(tls, timeout.Token);
        var root = new AsnReader(failure, AsnEncodingRules.DER).ReadSequence();
        Assert.Equal(version, (int)root.ReadSequence(Tag(0)).ReadInteger());
        if (version is 2 or 5)
        {
            var reject = root.ReadSequence(Tag(1)).ReadSequence().ReadSequence().ReadSequence(Tag(0)).ReadOctetString();
            var state = new AsnReader(reject, AsnEncodingRules.DER).ReadSequence(Tag(1)).ReadSequence()
                .ReadSequence(Tag(0)).ReadEnumeratedValue<NegotiationState>();
            Assert.Equal(NegotiationState.Reject, state);
        }
        else
        {
            var failureField = root.ReadSequence(Tag(4));
            Assert.True(failureField.TryReadInt32(out var failureCode));
            Assert.Equal(unchecked((int)0xC000006D), failureCode);
            failureField.ThrowIfNotEmpty();
        }
        root.ThrowIfNotEmpty();
        await server.WaitAsync(timeout.Token);
        var auth = Assert.Single(sink.Events, item => item.EventType == "AuthenticationAttempted");
        Assert.Equal("取证-user", auth.Username);
        Assert.Equal("TEST-DOMAIN", auth.Domain);
        Assert.Equal("CredSSP/NTLM", auth.AuthenticationMethod);
        Assert.Equal("STATUS_LOGON_FAILURE", auth.AuthenticationFailureCode);
        Assert.Equal("Response", auth.MaterialType);
        Assert.Null(auth.Password);
        var evidence = Assert.Single(sink.Evidence);
        Assert.Equal(auth.EventId, evidence.EventId);
        Assert.Equal(evidence.EventId, auth.CredentialArtifactId);
        using var content = JsonDocument.Parse(evidence.Content);
        Assert.Equal(challenge, content.RootElement.GetProperty("challenge").GetBytesFromBase64());
        Assert.Equal(authenticate, content.RootElement.GetProperty("authenticate").GetBytesFromBase64());
    }

    [Fact]
    public async Task ClientWithoutNlaGetsNegotiationFailureWithoutCredentialEvent()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(8));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var sink = new SshAuthenticationTests.EvidenceSink();
        var server = RunServer(listener, sink, timeout.Token);
        using var client = new TcpClient();
        await client.ConnectAsync((IPEndPoint)listener.LocalEndpoint, timeout.Token);
        using var stream = client.GetStream();
        await stream.WriteAsync(NegotiationRequest(1), timeout.Token);
        var failure = new byte[19];
        await stream.ReadExactlyAsync(failure, timeout.Token);
        Assert.Equal(3, failure[11]);
        Assert.Equal(5u, BinaryPrimitives.ReadUInt32LittleEndian(failure.AsSpan(15)));
        await server.WaitAsync(timeout.Token);
        Assert.Empty(sink.Evidence);
        Assert.DoesNotContain(sink.Events, item => item.EventType == "AuthenticationAttempted");
    }

    [Fact]
    public void NtlmParserRejectsTruncatedAndOutOfRangeSecurityBuffers()
    {
        var good = Authenticate("DOMAIN", "user", "CLIENT");
        Assert.True(NtlmProtocol.TryParse(good, out _));
        Assert.False(NtlmProtocol.TryParse(good.AsSpan(0, 63), out _));
        BinaryPrimitives.WriteUInt32LittleEndian(good.AsSpan(40), uint.MaxValue);
        Assert.False(NtlmProtocol.TryParse(good, out _));
        Assert.False(CredSspProtocol.TryReadRequest(new byte[] { 0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF }, out _));
    }

    private static async Task RunServer(TcpListener listener, SshAuthenticationTests.EvidenceSink sink, CancellationToken ct)
    {
        using var accepted = await listener.AcceptTcpClientAsync(ct);
        await using var session = new SshAuthenticationTests.SocketSession(accepted);
        await new RdpAdapter().HandleAsync(session, SshAuthenticationTests.Context(session, "rdp"), new ServiceProfile
        {
            ProfileId = "rdp-test", AdapterKey = "rdp", HandshakeTimeout = TimeSpan.FromSeconds(8),
        }, sink, ct);
    }

    private static byte[] NegotiationRequest(uint protocols)
    {
        byte[] request = [3, 0, 0, 19, 14, 0xE0, 0, 0, 0, 0, 0, 1, 0, 8, 0, 0, 0, 0, 0];
        BinaryPrimitives.WriteUInt32LittleEndian(request.AsSpan(15), protocols);
        return request;
    }

    private static byte[] Authenticate(string domain, string user, string workstation)
    {
        var fields = new[] { new byte[24], Enumerable.Repeat((byte)0xA5, 48).ToArray(), Encoding.Unicode.GetBytes(domain),
            Encoding.Unicode.GetBytes(user), Encoding.Unicode.GetBytes(workstation), Array.Empty<byte>() };
        var token = new byte[64 + fields.Sum(item => item.Length)];
        "NTLMSSP\0"u8.CopyTo(token);
        BinaryPrimitives.WriteUInt32LittleEndian(token.AsSpan(8), 3);
        BinaryPrimitives.WriteUInt32LittleEndian(token.AsSpan(60), 1);
        var offset = 64;
        for (var index = 0; index < fields.Length; index++)
        {
            var field = fields[index];
            var position = 12 + index * 8;
            BinaryPrimitives.WriteUInt16LittleEndian(token.AsSpan(position), (ushort)field.Length);
            BinaryPrimitives.WriteUInt16LittleEndian(token.AsSpan(position + 2), (ushort)field.Length);
            BinaryPrimitives.WriteUInt32LittleEndian(token.AsSpan(position + 4), (uint)offset);
            field.CopyTo(token, offset); offset += field.Length;
        }
        return token;
    }

    private static byte[] Request(byte[] token, int version, byte[]? binding = null, byte[]? nonce = null)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            using (writer.PushSequence(Tag(0))) writer.WriteInteger(version);
            using (writer.PushSequence(Tag(1)))
            using (writer.PushSequence())
            using (writer.PushSequence())
            using (writer.PushSequence(Tag(0))) writer.WriteOctetString(token);
            if (binding is not null)
            {
                using (writer.PushSequence(Tag(3))) writer.WriteOctetString(binding);
            }
            if (nonce is not null)
            {
                using (writer.PushSequence(Tag(5))) writer.WriteOctetString(nonce);
            }
        }
        return writer.Encode();
    }

    private static byte[] ReadNegoToken(byte[] request)
    {
        var sequence = new AsnReader(request, AsnEncodingRules.DER).ReadSequence();
        sequence.ReadSequence(Tag(0));
        return sequence.ReadSequence(Tag(1)).ReadSequence().ReadSequence().ReadSequence(Tag(0)).ReadOctetString();
    }

    private static async Task<byte[]> ReadDerAsync(Stream stream, CancellationToken ct)
    {
        var header = new byte[2]; await stream.ReadExactlyAsync(header, ct);
        var length = (int)header[1];
        byte[] extra = [];
        if ((length & 0x80) != 0)
        {
            extra = new byte[length & 0x7F]; await stream.ReadExactlyAsync(extra, ct);
            length = 0; foreach (var b in extra) length = (length << 8) | b;
        }
        Assert.InRange(length, 1, 65536);
        var payload = new byte[length]; await stream.ReadExactlyAsync(payload, ct);
        return header.Concat(extra).Concat(payload).ToArray();
    }
    private static Asn1Tag Tag(int value) => new(TagClass.ContextSpecific, value, true);
    private enum NegotiationState { Reject = 2 }
}
