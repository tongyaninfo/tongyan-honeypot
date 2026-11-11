using System.Buffers.Binary;
using System.Net;
using System.Text.Json;
using Honeypot.Protocols.Smb;
using SMBLibrary;
using SMBLibrary.Client;
using Xunit;

namespace Honeypot.Protocols.Tests;

public sealed class SmbAuthenticationTests
{
    [Theory]
    [InlineData(false, "0x0302")]
    [InlineData(true, "0x0311")]
    public async Task RealSmbClientReceivesLogonFailureAndRecordsOneNtlmResponse(bool smb311, string expectedDialect)
    {
        await using var server = new AuthenticationTestServer(new SmbAdapter(), AuthenticationTestServer.Profile("smb"));
        var client = new IsolatedSmbClient(smb311);
        try
        {
            Assert.True(await Task.Run(() => client.ConnectLoopback(server.Port)));
            var status = await Task.Run(() => client.Login("TEST-DOMAIN", "取证-user", "smb-isolated-sample"));
            Assert.Equal(NTStatus.STATUS_LOGON_FAILURE, status);
        }
        finally { client.Disconnect(); }
        var auth = await server.Sink.Authentication.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal("取证-user", auth.Username); Assert.Equal("TEST-DOMAIN", auth.Domain);
        Assert.Equal("SMB/NTLM", auth.AuthenticationMethod); Assert.Equal("STATUS_LOGON_FAILURE", auth.AuthenticationFailureCode);
        Assert.Equal("Response", auth.MaterialType); Assert.Null(auth.Password);
        Assert.Single(server.Sink.Events, e => e.EventType == "AuthenticationAttempted");
        using var evidence = JsonDocument.Parse(Assert.Single(server.Sink.Evidence).Content);
        Assert.Equal(expectedDialect, evidence.RootElement.GetProperty("dialect").GetString());
        Assert.False(evidence.RootElement.TryGetProperty("password", out _));
        var challenge = evidence.RootElement.GetProperty("challenge").GetBytesFromBase64();
        Assert.Equal(2u, BinaryPrimitives.ReadUInt32LittleEndian(challenge.AsSpan(8)));
        Assert.NotEmpty(evidence.RootElement.GetProperty("authenticate").GetBytesFromBase64());
        if (smb311) Assert.Equal(64, evidence.RootElement.GetProperty("preauthenticationHash").GetBytesFromBase64().Length);
        Assert.Empty(server.Errors);
    }

    [Fact]
    public async Task MalformedFrameCannotCreateAuthenticationOrEvidence()
    {
        await using var session = new AuthenticationByteSession([0x01, 0, 0, 64], fragmentSize: 1);
        var sink = new AuthenticationRecordingSink();
        await new SmbAdapter().HandleAsync(session, AuthenticationTestServer.Context("smb"), AuthenticationTestServer.Profile("smb"), sink);
        Assert.Empty(sink.Evidence);
        Assert.Contains(sink.Events, item => item.EventType == "ProtocolViolation");
    }

    [Fact]
    public async Task EvidenceFailureDoesNotSendNormalLogonFailureOrRecordSuccess()
    {
        await using var server = new AuthenticationTestServer(new SmbAdapter(), AuthenticationTestServer.Profile("smb"), failStorage: true);
        var client = new IsolatedSmbClient(false);
        try
        {
            Assert.True(await Task.Run(() => client.ConnectLoopback(server.Port)));
            var status = await Task.Run(() => client.Login("TEST-DOMAIN", "storage-test", "isolated-only"));
            Assert.NotEqual(NTStatus.STATUS_SUCCESS, status);
            Assert.NotEqual(NTStatus.STATUS_LOGON_FAILURE, status);
        }
        finally { client.Disconnect(); }
        Assert.Empty(server.Sink.Evidence);
        Assert.DoesNotContain(server.Sink.Events, item => item.EventType == "AuthenticationAttempted");
        Assert.Contains(server.Sink.Events, item => item.EventType == "CredentialCaptureFailed");
    }

    // 真实 SMBLibrary 客户端只将其保护的端口参数开放给隔离测试，认证/编解码逻辑不替换。
    private sealed class IsolatedSmbClient(bool smb311) : SMB2Client(4000, smb311)
    {
        public bool ConnectLoopback(int port) => Connect(IPAddress.Loopback, SMBTransportType.DirectTCPTransport, port);
    }
}
