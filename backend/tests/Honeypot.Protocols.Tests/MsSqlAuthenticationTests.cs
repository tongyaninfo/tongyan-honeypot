using System.Buffers.Binary;
using System.Formats.Asn1;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using Honeypot.Protocol.Abstractions.Models;
using Honeypot.Protocol.Abstractions.Service;
using Honeypot.Protocols.Common;
using Honeypot.Protocols.MsSql;
using Microsoft.Data.SqlClient;
using Xunit;

namespace Honeypot.Protocols.Tests;

public sealed class MsSqlAuthenticationTests
{
    [Theory]
    [InlineData("sa", "wrong-password")]
    [InlineData("用户", " 密码🔑 ")]
    [InlineData("", "")]
    public async Task SqlLoginPreservesCredentialsAndLinksEvidence(string username, string password)
    {
        var session = new BufferedSession(Packet(0x12, PreLogin()), Packet(0x10, Login(username, password)));
        var sink = new EvidenceSink();
        await new MsSqlAdapter().HandleAsync(session, Context(), Profile(), sink);
        var authentication = Assert.Single(sink.Events, item => item.EventType == "AuthenticationAttempted");
        Assert.Equal(username, authentication.Username);
        Assert.Equal("catalog", authentication.Database);
        Assert.Equal("sql-password", authentication.AuthenticationMethod);
        Assert.Equal("18456", authentication.AuthenticationFailureCode);
        Assert.Null(authentication.Password);
        var evidence = Assert.Single(sink.Evidence);
        Assert.Equal(authentication.EventId, evidence.EventId);
        Assert.Equal("Plaintext", evidence.MaterialType);
        using var json = JsonDocument.Parse(evidence.Content);
        Assert.Equal(password, json.RootElement.GetProperty("password").GetString());
        Assert.Equal(username, json.RootElement.GetProperty("username").GetString());
        Assert.DoesNotContain("\"Password\":", JsonSerializer.Serialize(authentication), StringComparison.OrdinalIgnoreCase);
        AssertLoginError(session.Writes.Last());
        Assert.Equal(SessionCloseReason.AdapterCompleted, session.CloseReason);
    }

    [Fact]
    public async Task FragmentedLoginIsReassembledBeforeAuthentication()
    {
        var login = Login("sa", "fragmented");
        var session = new BufferedSession(Packet(0x12, PreLogin()),
            Packet(0x10, login[..60], end: false, id: 1), Packet(0x10, login[60..], id: 2));
        var sink = new EvidenceSink();
        await new MsSqlAdapter().HandleAsync(session, Context(), Profile(), sink);
        Assert.Equal("sa", Assert.Single(sink.Events, item => item.EventType == "AuthenticationAttempted").Username);
        AssertLoginError(session.Writes.Last());
    }

    [Theory]
    [InlineData("wrong-type")]
    [InlineData("bad-offset")]
    [InlineData("bad-length")]
    [InlineData("bad-packet-id")]
    [InlineData("bad-prelogin")]
    public async Task InvalidFramesCannotMasqueradeAsAuthentication(string invalid)
    {
        var login = Login("sa", "wrong");
        var prelogin = PreLogin();
        if (invalid == "bad-offset") BinaryPrimitives.WriteUInt16LittleEndian(login.AsSpan(40), 8);
        if (invalid == "bad-length") BinaryPrimitives.WriteUInt32LittleEndian(login, 4);
        if (invalid == "bad-prelogin") prelogin = [0xFF];
        var frames = invalid == "bad-packet-id"
            ? new[] { Packet(0x12, prelogin), Packet(0x10, login[..50], false, 1), Packet(0x10, login[50..], true, 4) }
            : new[] { Packet(0x12, prelogin), Packet(invalid == "wrong-type" ? (byte)0x12 : (byte)0x10, login) };
        var session = new BufferedSession(frames);
        var sink = new EvidenceSink();
        await new MsSqlAdapter().HandleAsync(session, Context(), Profile(), sink);
        Assert.Empty(sink.Evidence);
        Assert.DoesNotContain(sink.Events, item => item.EventType == "AuthenticationAttempted");
        Assert.Contains(sink.Events, item => item.EventType == "ProtocolViolation");
        Assert.Equal(SessionCloseReason.ProtocolViolation, session.CloseReason);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task NtlmChallengeResponseCapturesIdentityAndTranscript(bool spnego)
    {
        var type1 = new byte[32];
        "NTLMSSP\0"u8.CopyTo(type1);
        BinaryPrimitives.WriteUInt32LittleEndian(type1.AsSpan(8), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(type1.AsSpan(12), 0x00880201);
        var type3 = NtlmAuthenticate("EXAMPLE", "tester");
        if (spnego) { type1 = Spnego(type1, initial: true); type3 = Spnego(type3, initial: false); }
        var session = new BufferedSession(Packet(0x12, PreLogin()), Packet(0x10, Login("", "", type1)), Packet(0x11, type3));
        var sink = new EvidenceSink();
        await new MsSqlAdapter().HandleAsync(session, Context(), Profile(), sink);
        Assert.Contains(sink.Events, item => item.EventType == "SspiChallengeSent");
        var auth = Assert.Single(sink.Events, item => item.EventType == "AuthenticationAttempted");
        Assert.Equal("ntlm", auth.AuthenticationMethod);
        Assert.Equal("tester", auth.Username);
        Assert.Equal("EXAMPLE", auth.Domain);
        var evidence = Assert.Single(sink.Evidence);
        Assert.Equal("Response", evidence.MaterialType);
        using var json = JsonDocument.Parse(evidence.Content);
        var challenge = Convert.FromBase64String(json.RootElement.GetProperty("challenge").GetString()!);
        Assert.Equal(2u, BinaryPrimitives.ReadUInt32LittleEndian(challenge.AsSpan(8)));
        Assert.Equal(type3, Convert.FromBase64String(json.RootElement.GetProperty("authenticate").GetString()!));
        Assert.False(json.RootElement.TryGetProperty("password", out _));
        AssertLoginError(session.Writes.Last());
    }

    [Fact]
    public async Task OversizedMessageIsRejectedBeforeCredentialCapture()
    {
        var session = new BufferedSession(Packet(0x12, PreLogin()), Packet(0x10, Login("sa", "wrong")));
        var sink = new EvidenceSink();
        await new MsSqlAdapter().HandleAsync(session, Context(), Profile() with { MaxFrameBytes = 128 }, sink);
        Assert.Equal(SessionCloseReason.ResourceLimitExceeded, session.CloseReason);
        Assert.Contains(sink.Events, item => item.EventType == "ResourceLimitExceeded");
        Assert.Empty(sink.Evidence);
    }

    [Fact]
    public async Task SlowHandshakeUsesOneDeadlineAndClosesSession()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        using var client = new TcpClient();
        await client.ConnectAsync((IPEndPoint)listener.LocalEndpoint);
        using var accepted = await listener.AcceptTcpClientAsync();
        await using var session = new NetworkSession(accepted);
        var sink = new EvidenceSink();
        await new MsSqlAdapter().HandleAsync(session, Context(), Profile() with { HandshakeTimeout = TimeSpan.FromMilliseconds(50) }, sink);
        Assert.True(session.IsClosed);
        Assert.Contains(sink.Events, item => item.EventType == "HandshakeTimeout");
        Assert.Empty(sink.Evidence);
    }

    [Fact]
    public async Task EvidenceFailureTerminatesBeforeSendingLoginResult()
    {
        var session = new BufferedSession(Packet(0x12, PreLogin()), Packet(0x10, Login("sa", "wrong")));
        var sink = new EvidenceSink { FailStore = true };
        await Assert.ThrowsAsync<AuthenticationRecordingException>(async () =>
            await new MsSqlAdapter().HandleAsync(session, Context(), Profile(), sink));
        Assert.Single(session.Writes); // 只有 PreLogin，不伪造已记录的认证结果。
        Assert.True(session.IsClosed);
        Assert.Contains(sink.Events, item => item.EventType == "CredentialCaptureFailed");
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task RealSqlClientReceives18456AfterTlsAndPasswordCapture(bool encrypt)
    {
        // 仅在临时回环端口接受合成凭据；不启动 SQL Server、不连接真实数据库。
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var endpoint = (IPEndPoint)listener.LocalEndpoint;
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var sink = new EvidenceSink();
        var server = Task.Run(async () =>
        {
            using var accepted = await listener.AcceptTcpClientAsync(timeout.Token);
            await using var session = new NetworkSession(accepted);
            await new MsSqlAdapter().HandleAsync(session, Context(), Profile(), sink, timeout.Token);
        }, timeout.Token);
        var builder = new SqlConnectionStringBuilder
        {
            DataSource = $"tcp:127.0.0.1,{endpoint.Port}", UserID = "test_user", Password = "synthetic_wrong_password",
            InitialCatalog = "test_catalog", Encrypt = encrypt ? SqlConnectionEncryptOption.Mandatory : SqlConnectionEncryptOption.Optional,
            TrustServerCertificate = true, Pooling = false, ConnectTimeout = 10, ConnectRetryCount = 0,
        };
        await using var connection = new SqlConnection(builder.ConnectionString);
        var error = await Assert.ThrowsAsync<SqlException>(() => connection.OpenAsync(timeout.Token));
        await server.WaitAsync(timeout.Token);
        Assert.Equal(18456, error.Number);
        Assert.Contains(sink.Events, item => item.EventType == "TlsHandshakeCompleted");
        var authentication = Assert.Single(sink.Events, item => item.EventType == "AuthenticationAttempted");
        Assert.Equal("test_user", authentication.Username);
        Assert.Equal("test_catalog", authentication.Database);
        using var evidence = JsonDocument.Parse(Assert.Single(sink.Evidence).Content);
        Assert.Equal("synthetic_wrong_password", evidence.RootElement.GetProperty("password").GetString());
    }

    private static ServiceProfile Profile() => new()
    {
        ProfileId = "test-profile", AdapterKey = "mssql", AdvertisedHostName = "sql.example.test",
        HandshakeTimeout = TimeSpan.FromSeconds(12), MaxFrameBytes = 65536,
    };
    private static ProtocolSessionContext Context() => new("test-connection", "test-instance", "test-listener",
        "mssql", "test-profile", new IPEndPoint(IPAddress.Loopback, 50001),
        new IPEndPoint(IPAddress.Loopback, 50002), DateTimeOffset.UtcNow);
    private static byte[] PreLogin() => [0, 0, 11, 0, 6, 1, 0, 17, 0, 1, 0xFF, 15, 0, 0, 0, 0, 0, 2];
    private static byte[] Login(string username, string password, byte[]? sspi = null)
    {
        using var payload = new MemoryStream();
        payload.Write(new byte[94]);
        var fields = new[] { (36, "client-host", false), (40, username, false), (44, password, true), (48, "test-client", false), (68, "catalog", false) };
        foreach (var (pair, value, isPassword) in fields)
        {
            var data = Encoding.Unicode.GetBytes(value);
            if (isPassword)
                for (var index = 0; index < data.Length; index++) data[index] = (byte)((((data[index] << 4) | (data[index] >> 4)) ^ 0xA5) & 0xFF);
            var offset = payload.Position;
            payload.Position = pair;
            payload.Write(BitConverter.GetBytes((ushort)offset));
            payload.Write(BitConverter.GetBytes((ushort)value.Length));
            payload.Position = offset;
            payload.Write(data);
        }
        if (sspi is not null)
        {
            var offset = payload.Position;
            payload.Position = 78;
            payload.Write(BitConverter.GetBytes((ushort)offset));
            payload.Write(BitConverter.GetBytes((ushort)sspi.Length));
            payload.Position = offset;
            payload.Write(sspi);
        }
        var result = payload.ToArray();
        BinaryPrimitives.WriteUInt32LittleEndian(result, (uint)result.Length);
        BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(4), 0x74000004);
        BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(8), 4096);
        if (sspi is not null) result[25] = 0x80;
        return result;
    }
    private static byte[] Packet(byte type, byte[] payload, bool end = true, byte id = 1)
    {
        var frame = new byte[payload.Length + 8];
        frame[0] = type;
        frame[1] = end ? (byte)1 : (byte)0;
        BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(2), (ushort)frame.Length);
        frame[6] = id;
        payload.CopyTo(frame, 8);
        return frame;
    }
    private static byte[] NtlmAuthenticate(string domain, string username)
    {
        var values = new[] { Array.Empty<byte>(), Enumerable.Repeat((byte)0x11, 24).ToArray(), Encoding.Unicode.GetBytes(domain), Encoding.Unicode.GetBytes(username), Encoding.Unicode.GetBytes("CLIENT"), Array.Empty<byte>() };
        var token = new byte[64 + values.Sum(item => item.Length)];
        "NTLMSSP\0"u8.CopyTo(token);
        BinaryPrimitives.WriteUInt32LittleEndian(token.AsSpan(8), 3);
        BinaryPrimitives.WriteUInt32LittleEndian(token.AsSpan(60), 1);
        var offset = 64;
        for (var index = 0; index < values.Length; index++)
        {
            var field = 12 + index * 8;
            BinaryPrimitives.WriteUInt16LittleEndian(token.AsSpan(field), (ushort)values[index].Length);
            BinaryPrimitives.WriteUInt16LittleEndian(token.AsSpan(field + 2), (ushort)values[index].Length);
            BinaryPrimitives.WriteUInt32LittleEndian(token.AsSpan(field + 4), (uint)offset);
            values[index].CopyTo(token, offset);
            offset += values[index].Length;
        }
        return token;
    }
    private static byte[] Spnego(byte[] token, bool initial)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        var application = new Asn1Tag(TagClass.Application, 0, true);
        var negotiation = new Asn1Tag(TagClass.ContextSpecific, initial ? 0 : 1, true);
        var mechanisms = new Asn1Tag(TagClass.ContextSpecific, 0, true);
        var response = new Asn1Tag(TagClass.ContextSpecific, 2, true);
        if (initial) { writer.PushSequence(application); writer.WriteObjectIdentifier("1.3.6.1.5.5.2"); }
        using (writer.PushSequence(negotiation))
        using (writer.PushSequence())
        {
            if (initial)
            {
                using (writer.PushSequence(mechanisms))
                using (writer.PushSequence()) writer.WriteObjectIdentifier("1.3.6.1.4.1.311.2.2.10");
            }
            using (writer.PushSequence(response)) writer.WriteOctetString(token);
        }
        if (initial) writer.PopSequence(application);
        return writer.Encode();
    }
    private static void AssertLoginError(byte[] response)
    {
        Assert.Equal(4, response[0]);
        Assert.Equal(0xAA, response[8]);
        Assert.Equal(18456, BinaryPrimitives.ReadInt32LittleEndian(response.AsSpan(11)));
        var done = 11 + BinaryPrimitives.ReadUInt16LittleEndian(response.AsSpan(9));
        Assert.Equal(0xFD, response[done]);
        Assert.Equal(2, BinaryPrimitives.ReadUInt16LittleEndian(response.AsSpan(done + 1)));
    }
    private sealed class EvidenceSink : IInteractionEventSink, ICredentialEvidenceSink
    {
        public List<InteractionEvent> Events { get; } = [];
        public List<CredentialEvidence> Evidence { get; } = [];
        public bool FailStore { get; init; }
        public ValueTask<EventAppendResult> AppendAsync(InteractionEvent interactionEvent, CancellationToken cancellationToken = default)
        { Events.Add(interactionEvent); return ValueTask.FromResult(EventAppendResult.Accepted()); }
        public ValueTask<string> StoreAsync(CredentialEvidence evidence, CancellationToken cancellationToken = default)
        {
            if (FailStore) throw new IOException("Synthetic storage failure");
            Evidence.Add(evidence with { Content = evidence.Content.ToArray() });
            return ValueTask.FromResult("test-evidence");
        }
    }
    private sealed class BufferedSession(params byte[][] frames) : IHoneypotSession
    {
        private readonly MemoryStream _input = new(frames.SelectMany(item => item).ToArray());
        public List<byte[]> Writes { get; } = [];
        public SessionCloseReason? CloseReason { get; private set; }
        public string ConnectionId => "test-connection";
        public EndPoint RemoteEndPoint => new IPEndPoint(IPAddress.Loopback, 50001);
        public EndPoint LocalEndPoint => new IPEndPoint(IPAddress.Loopback, 50002);
        public string Transport => "tcp";
        public bool IsClosed => CloseReason.HasValue;
        public ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct) => _input.ReadAsync(buffer[..Math.Min(buffer.Length, 3)], ct);
        public ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct) { Writes.Add(buffer.ToArray()); return ValueTask.CompletedTask; }
        public ValueTask CloseAsync(SessionCloseReason reason, CancellationToken ct = default) { CloseReason = reason; return ValueTask.CompletedTask; }
        public ValueTask DisposeAsync() => _input.DisposeAsync();
    }
    private sealed class NetworkSession(TcpClient client) : IHoneypotSession
    {
        public string ConnectionId => "test-connection";
        public EndPoint RemoteEndPoint => client.Client.RemoteEndPoint!;
        public EndPoint LocalEndPoint => client.Client.LocalEndPoint!;
        public string Transport => "tcp";
        public bool IsClosed { get; private set; }
        public ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct) => client.GetStream().ReadAsync(buffer, ct);
        public ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct) => client.GetStream().WriteAsync(buffer, ct);
        public ValueTask CloseAsync(SessionCloseReason reason, CancellationToken ct = default) { IsClosed = true; client.Close(); return ValueTask.CompletedTask; }
        public ValueTask DisposeAsync() { client.Dispose(); return ValueTask.CompletedTask; }
    }
}
