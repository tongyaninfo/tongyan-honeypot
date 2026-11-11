using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using Honeypot.Protocol.Abstractions.Models;
using Honeypot.Protocol.Abstractions.Service;
using Honeypot.Runtime.Service;
using Honeypot.Protocols.Mongo;
using Honeypot.Protocols.MySql;
using Honeypot.Protocols.Rdp;
using Honeypot.Protocols.Common;
using Honeypot.Protocols.Ssh;
using Honeypot.Api.Service.impl;
using Honeypot.Engine.Service.impl;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Honeypot.Runtime.Tests;

public sealed class RuntimeTests
{
    [Fact]
    public void RegistryRejectsDuplicateAdapterKeys()
    {
        var registry = new ProtocolAdapterRegistry();
        registry.Register(new NoopAdapter("ssh"));

        Assert.Throws<InvalidOperationException>(() => registry.Register(new NoopAdapter("SSH")));
    }

    [Fact]
    public async Task ListenerRecordsConnectionBeforeAdapterRuns()
    {
        var port = GetFreePort();
        var registry = new ProtocolAdapterRegistry();
        var sink = new InMemoryInteractionEventSink();
        registry.Register(new NoopAdapter("ssh"));
        await using var host = new TcpListenerHost(
            registry,
            sink,
            new ConnectionIdGenerator(),
            NullLogger<TcpListenerHost>.Instance);

        var instance = new ServiceInstance
        {
            InstanceId = "ssh-test",
            DisplayName = "SSH test",
            AdapterKey = "ssh",
            Profile = new ServiceProfile { ProfileId = "profile-ssh", AdapterKey = "ssh" },
            Bindings = new[]
            {
                new ListenerBinding
                {
                    ListenerId = "ssh-test-1",
                    BindAddress = "127.0.0.1",
                    Port = port,
                    MaxConnections = 10,
                    MaxConnectionsPerIp = 10,
                },
            },
        };

        var applied = await host.ApplyAsync(instance);
        Assert.True(applied.Succeeded, applied.Message);
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port);

        var deadline = DateTime.UtcNow.AddSeconds(2);
        while (sink.Events.Count == 0 && DateTime.UtcNow < deadline)
        {
            await Task.Delay(10);
        }

        var accepted = Assert.Single(sink.Events, item => item.EventType == "ConnectionAccepted");
        Assert.Equal("ConnectionAccepted", accepted.EventType);
        Assert.Equal(port, accepted.DestinationPort);
        Assert.Equal("ssh-test-1", accepted.ListenerId);
        Assert.Equal("ssh-test", accepted.ServiceInstanceId);
    }

    [Fact]
    public async Task SshKeepsTheWireSessionOpenAfterIdentificationExchange()
    {
        var port = GetFreePort();
        var registry = new ProtocolAdapterRegistry();
        registry.Register(new SshAdapter());
        await using var host = new TcpListenerHost(
            registry,
            new InMemoryInteractionEventSink(),
            new ConnectionIdGenerator(),
            NullLogger<TcpListenerHost>.Instance);

        var instance = CreateInstance("ssh-wire", port) with
        {
            Profile = new ServiceProfile
            {
                ProfileId = "profile-ssh-wire",
                AdapterKey = "ssh",
                AdvertisedProduct = "OpenSSH",
                AdvertisedVersion = "9.6p1 Ubuntu-3ubuntu13.5",
                HandshakeTimeout = TimeSpan.FromSeconds(2),
            },
        };

        var applied = await host.ApplyAsync(instance);
        Assert.True(applied.Succeeded, applied.Message);

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port);
        await using var stream = client.GetStream();

        var serverBanner = await ReadLineAsync(stream, TimeSpan.FromSeconds(2));
        Assert.StartsWith("SSH-2.0-", serverBanner, StringComparison.Ordinal);

        var clientBanner = Encoding.ASCII.GetBytes("SSH-2.0-OpenSSH_9.6p1\r\n");
        await stream.WriteAsync(clientBanner);
        await stream.FlushAsync();

        // 版本交换后，服务端应发送明文 SSH_MSG_KEXINIT，而不是立即关闭套接字。
        var lengthBytes = new byte[4];
        await ReadExactlyAsync(stream, lengthBytes, TimeSpan.FromSeconds(2));
        var packetLength = System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(lengthBytes);
        Assert.InRange(packetLength, 16u, 1024u * 1024u);
        var packet = new byte[checked((int)packetLength)];
        await ReadExactlyAsync(stream, packet, TimeSpan.FromSeconds(2));
        Assert.Equal(20, packet[1]);
    }

    [Fact]
    public async Task MysqlCompletesInitialHandshakeAndReturnsProtocolError()
    {
        var port = GetFreePort();
        var registry = new ProtocolAdapterRegistry();
        registry.Register(new MySqlAdapter());
        using var evidenceStore = new InMemoryCredentialEvidenceStore();
        var eventStore = new InMemoryInteractionEventStore(new InMemoryThreatProfileStore(), evidenceStore);
        await using var host = new TcpListenerHost(
            registry,
            eventStore,
            new ConnectionIdGenerator(),
            NullLogger<TcpListenerHost>.Instance);
        var applied = await host.ApplyAsync(CreateInstance("mysql-wire", port, "mysql") with
        {
            Profile = new ServiceProfile
            {
                ProfileId = "profile-mysql-wire",
                AdapterKey = "mysql",
                MySqlAuthenticationPlugin = "mysql_native_password",
                HandshakeTimeout = TimeSpan.FromSeconds(2),
            },
        });
        Assert.True(applied.Succeeded, applied.Message);

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port);
        await using var stream = client.GetStream();
        var handshake = await ReadMysqlPacketAsync(stream);
        Assert.Contains("MySQL Community Server", Encoding.ASCII.GetString(handshake), StringComparison.Ordinal);

        using var login = new MemoryStream();
        using (var writer = new BinaryWriter(login, Encoding.UTF8, true))
        {
            writer.Write(0x00088200u); // Protocol41 / SecureConnection / PluginAuth。
            writer.Write(1024 * 1024); writer.Write((byte)45); writer.Write(new byte[23]);
            writer.Write(Encoding.UTF8.GetBytes("e2e-user\0"));
            writer.Write((byte)20); writer.Write(Enumerable.Repeat((byte)42, 20).ToArray());
            writer.Write(Encoding.ASCII.GetBytes("mysql_native_password\0"));
        }
        var payload = login.ToArray();
        await stream.WriteAsync(new byte[] { (byte)payload.Length, 0, 0, 1 });
        await stream.WriteAsync(payload);
        await stream.FlushAsync();
        var error = await ReadMysqlPacketAsync(stream);
        Assert.Contains("Access denied", Encoding.ASCII.GetString(error), StringComparison.Ordinal);
        var authentication = Assert.Single(eventStore.GetAll(), item => item.EventType == "AuthenticationAttempted");
        Assert.Equal("e2e-user", authentication.Username);
        Assert.True(authentication.Sequence > 1);
        var evidence = evidenceStore.Get(authentication.CredentialArtifactId!);
        Assert.NotNull(evidence);
        Assert.Equal(authentication.EventId, evidence.Summary.EventId);
        Assert.Equal(authentication.ConnectionId, evidence.Summary.ConnectionId);
        Assert.Contains("e2e-user", evidence.Content);
        Assert.Equal("Response", evidence.Summary.MaterialType);
        Assert.Null(authentication.Password);
    }

    [Fact]
    public async Task MongoCompletesHelloExchangeBeforeClosing()
    {
        var port = GetFreePort();
        var registry = new ProtocolAdapterRegistry();
        registry.Register(new MongoAdapter());
        await using var host = new TcpListenerHost(
            registry,
            new InMemoryInteractionEventSink(),
            new ConnectionIdGenerator(),
            NullLogger<TcpListenerHost>.Instance);
        var applied = await host.ApplyAsync(CreateInstance("mongodb-wire", port, "mongodb") with
        {
            Profile = new ServiceProfile
            {
                ProfileId = "profile-mongodb-wire",
                AdapterKey = "mongodb",
                HandshakeTimeout = TimeSpan.FromSeconds(2),
            },
        });
        Assert.True(applied.Succeeded, applied.Message);

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port);
        await using var stream = client.GetStream();
        using var document = new MemoryStream();
        using (var writer = new BinaryWriter(document, Encoding.UTF8, true))
        {
            writer.Write(31);
            writer.Write((byte)16); writer.Write(Encoding.ASCII.GetBytes("hello\0")); writer.Write(1);
            writer.Write((byte)2); writer.Write(Encoding.ASCII.GetBytes("$db\0")); writer.Write(6); writer.Write(Encoding.ASCII.GetBytes("admin\0"));
            writer.Write((byte)0);
        }
        var request = new byte[21 + document.Length];
        System.Buffers.Binary.BinaryPrimitives.WriteInt32LittleEndian(request.AsSpan(0, 4), request.Length);
        System.Buffers.Binary.BinaryPrimitives.WriteInt32LittleEndian(request.AsSpan(4, 4), 7);
        System.Buffers.Binary.BinaryPrimitives.WriteInt32LittleEndian(request.AsSpan(12, 4), 2013);
        document.ToArray().CopyTo(request, 21);
        await stream.WriteAsync(request);
        await stream.FlushAsync();

        var responseLengthBytes = new byte[4];
        await ReadExactlyAsync(stream, responseLengthBytes, TimeSpan.FromSeconds(2));
        var responseLength = System.Buffers.Binary.BinaryPrimitives.ReadInt32LittleEndian(responseLengthBytes);
        Assert.InRange(responseLength, 16, 1024 * 1024);
        var response = new byte[responseLength - 4];
        await ReadExactlyAsync(stream, response, TimeSpan.FromSeconds(2));
        Assert.Equal(2013, System.Buffers.Binary.BinaryPrimitives.ReadInt32LittleEndian(response.AsSpan(8, 4)));
        Assert.Contains("mongo-db-01", Encoding.UTF8.GetString(response), StringComparison.Ordinal);
    }

    [Fact]
    public async Task RdpCompletesTlsHandshakeAfterX224Confirm()
    {
        var port = GetFreePort();
        var registry = new ProtocolAdapterRegistry();
        var sink = new RdpEvidenceSink();
        registry.Register(new RdpAdapter());
        await using var host = new TcpListenerHost(
            registry,
            sink,
            new ConnectionIdGenerator(),
            NullLogger<TcpListenerHost>.Instance);
        var applied = await host.ApplyAsync(CreateInstance("rdp-wire", port, "rdp") with
        {
            Profile = new ServiceProfile
            {
                ProfileId = "profile-rdp-wire",
                AdapterKey = "rdp",
                HandshakeTimeout = TimeSpan.FromSeconds(2),
            },
        });
        Assert.True(applied.Succeeded, applied.Message);

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port);
        await using var stream = client.GetStream();
        await stream.WriteAsync(new byte[]
        {
            0x03, 0x00, 0x00, 0x13, 0x0E, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00,
        });
        await stream.FlushAsync();

        var confirm = new byte[19];
        await ReadExactlyAsync(stream, confirm, TimeSpan.FromSeconds(2));
        Assert.Equal(0x03, confirm[0]);
        Assert.Equal(0x02, confirm[11]);

        using var tls = new SslStream(stream, leaveInnerStreamOpen: true);
        await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
        {
            TargetHost = "WIN-7F3A1C2",
            EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
            RemoteCertificateValidationCallback = (_, _, _, _) => true,
        });

        var tlsDeadline = DateTime.UtcNow.AddSeconds(2);
        while (!sink.Events.Any(item => item.EventType == "TlsHandshakeCompleted") && DateTime.UtcNow < tlsDeadline) await Task.Delay(10);
        Assert.Contains(sink.Events, item => item.EventType == "TlsHandshakeCompleted");
    }

    [Fact]
    public async Task RdpCredSspType3IsRejectedWithFailureAndIdentityRecorded()
    {
        var port = GetFreePort();
        var registry = new ProtocolAdapterRegistry();
        var sink = new RdpEvidenceSink();
        registry.Register(new RdpAdapter());
        await using var host = new TcpListenerHost(
            registry,
            sink,
            new ConnectionIdGenerator(),
            NullLogger<TcpListenerHost>.Instance);
        var applied = await host.ApplyAsync(CreateInstance("rdp-credssp-wire", port, "rdp") with
        {
            Profile = new ServiceProfile
            {
                ProfileId = "profile-rdp-credssp-wire",
                AdapterKey = "rdp",
                HandshakeTimeout = TimeSpan.FromSeconds(3),
            },
        });
        Assert.True(applied.Succeeded, applied.Message);

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port);
        await using var stream = client.GetStream();
        await stream.WriteAsync(new byte[]
        {
            0x03, 0x00, 0x00, 0x13, 0x0E, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00,
        });
        await stream.FlushAsync();

        var confirm = new byte[19];
        await ReadExactlyAsync(stream, confirm, TimeSpan.FromSeconds(2));
        using var tls = new SslStream(stream, leaveInnerStreamOpen: true);
        await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
        {
            TargetHost = "WIN-RDP-01",
            EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
            RemoteCertificateValidationCallback = (_, _, _, _) => true,
        });

        var type1 = new byte[32];
        Encoding.ASCII.GetBytes("NTLMSSP\0").CopyTo(type1, 0);
        BitConverter.GetBytes(1u).CopyTo(type1, 8);
        BitConverter.GetBytes(0x00888235u).CopyTo(type1, 12);
        await tls.WriteAsync(CredSspProtocol.BuildSpnegoAuthenticationRequest(type1));
        await tls.FlushAsync();
        var challengeRequest = await ReadDerMessageAsync(tls, TimeSpan.FromSeconds(2));
        Assert.True(CredSspProtocol.TryExtractNtlmToken(challengeRequest, out var challenge));
        Assert.Equal(2u, BitConverter.ToUInt32(challenge, 8));

        var type3 = BuildNtlmType3("CONTOSO", "alice", "WIN-CLIENT");
        await tls.WriteAsync(CredSspProtocol.BuildSpnegoAuthenticationRequest(type3));
        await tls.FlushAsync();
        var failure = await ReadDerMessageAsync(tls, TimeSpan.FromSeconds(2));

        Assert.Equal((byte)0x30, failure[0]);
        Assert.Contains((byte)0xA4, failure);
        var deadline = DateTime.UtcNow.AddSeconds(2);
        while (!sink.Events.Any(item => item.EventType == "AuthenticationAttempted") && DateTime.UtcNow < deadline)
        {
            await Task.Delay(10);
        }

        var authentication = Assert.Single(sink.Events, item => item.EventType == "AuthenticationAttempted");
        Assert.Equal("failure", authentication.Outcome);
        Assert.Equal("alice", authentication.Username);
    }

    private static async Task<string> ReadLineAsync(NetworkStream stream, TimeSpan timeout)
    {
        var bytes = new List<byte>(128);
        using var cancellation = new CancellationTokenSource(timeout);
        while (true)
        {
            var one = new byte[1];
            var count = await stream.ReadAsync(one, cancellation.Token);
            Assert.NotEqual(0, count);
            bytes.Add(one[0]);
            if (one[0] == (byte)'\n')
            {
                return Encoding.ASCII.GetString(bytes.ToArray()).TrimEnd('\r', '\n');
            }
        }
    }

    private static async Task ReadExactlyAsync(NetworkStream stream, byte[] buffer, TimeSpan timeout)
    {
        using var cancellation = new CancellationTokenSource(timeout);
        var offset = 0;
        while (offset < buffer.Length)
        {
            var count = await stream.ReadAsync(buffer.AsMemory(offset), cancellation.Token);
            Assert.NotEqual(0, count);
            offset += count;
        }
    }

    private static async Task<byte[]> ReadMysqlPacketAsync(NetworkStream stream)
    {
        var header = new byte[4];
        await ReadExactlyAsync(stream, header, TimeSpan.FromSeconds(2));
        var payloadLength = header[0] | (header[1] << 8) | (header[2] << 16);
        Assert.InRange(payloadLength, 1, 1024 * 1024);
        var payload = new byte[payloadLength];
        await ReadExactlyAsync(stream, payload, TimeSpan.FromSeconds(2));
        return payload;
    }

    private static async Task<byte[]> ReadDerMessageAsync(Stream stream, TimeSpan timeout)
    {
        using var cancellation = new CancellationTokenSource(timeout);
        var header = new byte[2];
        await ReadExactlyAsync(stream, header, cancellation.Token);
        Assert.Equal((byte)0x30, header[0]);
        var length = (int)header[1];
        var lengthBytes = Array.Empty<byte>();
        if ((length & 0x80) != 0)
        {
            lengthBytes = new byte[length & 0x7F];
            await ReadExactlyAsync(stream, lengthBytes, cancellation.Token);
            length = 0;
            foreach (var value in lengthBytes) length = (length << 8) | value;
        }

        var message = new byte[2 + lengthBytes.Length + length];
        header.CopyTo(message, 0);
        lengthBytes.CopyTo(message, 2);
        await ReadExactlyAsync(stream, message.AsMemory(2 + lengthBytes.Length), cancellation.Token);
        return message;
    }

    private static byte[] BuildNtlmType3(string domain, string user, string workstation)
    {
        var domainBytes = Encoding.Unicode.GetBytes(domain);
        var userBytes = Encoding.Unicode.GetBytes(user);
        var workstationBytes = Encoding.Unicode.GetBytes(workstation);
        var lm = new byte[24];
        var nt = new byte[24];
        var payloadOffset = 64;
        var message = new byte[payloadOffset + lm.Length + nt.Length + domainBytes.Length + userBytes.Length + workstationBytes.Length];
        Encoding.ASCII.GetBytes("NTLMSSP\0").CopyTo(message, 0);
        BitConverter.GetBytes(3u).CopyTo(message, 8);
        WriteNtlmBuffer(message, 12, lm.Length, payloadOffset); payloadOffset += lm.Length;
        WriteNtlmBuffer(message, 20, nt.Length, payloadOffset); payloadOffset += nt.Length;
        WriteNtlmBuffer(message, 28, domainBytes.Length, payloadOffset); domainBytes.CopyTo(message, payloadOffset); payloadOffset += domainBytes.Length;
        WriteNtlmBuffer(message, 36, userBytes.Length, payloadOffset); userBytes.CopyTo(message, payloadOffset); payloadOffset += userBytes.Length;
        WriteNtlmBuffer(message, 44, workstationBytes.Length, payloadOffset); workstationBytes.CopyTo(message, payloadOffset); payloadOffset += workstationBytes.Length;
        WriteNtlmBuffer(message, 52, 0, payloadOffset);
        BitConverter.GetBytes(1u).CopyTo(message, 60);
        return message;
    }

    private static void WriteNtlmBuffer(byte[] message, int offset, int length, int dataOffset)
    {
        BitConverter.GetBytes((ushort)length).CopyTo(message, offset);
        BitConverter.GetBytes((ushort)length).CopyTo(message, offset + 2);
        BitConverter.GetBytes((uint)dataOffset).CopyTo(message, offset + 4);
    }

    private static async Task ReadExactlyAsync(Stream stream, Memory<byte> buffer, CancellationToken cancellationToken)
    {
        var offset = 0;
        while (offset < buffer.Length)
        {
            var count = await stream.ReadAsync(buffer[offset..], cancellationToken);
            Assert.NotEqual(0, count);
            offset += count;
        }
    }

    [Fact]
    public async Task InvalidBindingIsRejected()
    {
        var registry = new ProtocolAdapterRegistry();
        registry.Register(new NoopAdapter("ssh"));
        await using var host = new TcpListenerHost(
            registry,
            new InMemoryInteractionEventSink(),
            new ConnectionIdGenerator(),
            NullLogger<TcpListenerHost>.Instance);

        var result = await host.ApplyAsync(new ServiceInstance
        {
            InstanceId = "invalid",
            DisplayName = "Invalid",
            AdapterKey = "ssh",
            Profile = new ServiceProfile { ProfileId = "profile-ssh", AdapterKey = "ssh" },
            Bindings = new[]
            {
                new ListenerBinding { ListenerId = "invalid-port", BindAddress = "127.0.0.1", Port = 0 },
            },
        });

        Assert.False(result.Succeeded);
        Assert.Equal("INVALID_PORT", result.Code);
    }

    [Fact]
    public async Task ApplyingUpdatedPortsReleasesTheOldSocket()
    {
        var firstPort = GetFreePort();
        var secondPort = GetFreePort();
        var registry = new ProtocolAdapterRegistry();
        registry.Register(new NoopAdapter("ssh"));
        await using var host = new TcpListenerHost(
            registry,
            new InMemoryInteractionEventSink(),
            new ConnectionIdGenerator(),
            NullLogger<TcpListenerHost>.Instance);

        var original = CreateInstance("ssh-edit", firstPort);
        var applied = await host.ApplyAsync(original);
        Assert.True(applied.Succeeded, applied.Message);

        var updated = original with
        {
            Bindings = new[]
            {
                original.Bindings[0] with { Port = secondPort },
            },
        };

        var replaced = await host.ApplyAsync(updated);
        Assert.True(replaced.Succeeded, replaced.Message);
        Assert.Contains(host.GetStatuses(), item => item.Port == secondPort);
        Assert.DoesNotContain(host.GetStatuses(), item => item.Port == firstPort);

        using var oldPortProbe = new TcpListener(IPAddress.Loopback, firstPort);
        oldPortProbe.Start();
    }

    [Fact]
    public async Task BindConflictIncludesTheEndpointInTheFailureMessage()
    {
        var port = GetFreePort();
        using var occupied = new TcpListener(IPAddress.Loopback, port);
        occupied.Start();

        var registry = new ProtocolAdapterRegistry();
        registry.Register(new NoopAdapter("ssh"));
        await using var host = new TcpListenerHost(
            registry,
            new InMemoryInteractionEventSink(),
            new ConnectionIdGenerator(),
            NullLogger<TcpListenerHost>.Instance);

        var result = await host.ApplyAsync(CreateInstance("bind-conflict", port));

        Assert.False(result.Succeeded);
        Assert.Equal("BIND_FAILED", result.Code);
        Assert.Contains($"127.0.0.1:{port}/tcp", result.Message, StringComparison.Ordinal);
        Assert.Contains("更换端口", result.Message, StringComparison.Ordinal);
    }

    private static int GetFreePort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }

    private static ServiceInstance CreateInstance(string instanceId, int port, string adapterKey = "ssh") => new()
    {
        InstanceId = instanceId,
        DisplayName = instanceId,
        AdapterKey = adapterKey,
        Profile = new ServiceProfile { ProfileId = $"profile-{instanceId}", AdapterKey = adapterKey },
        Bindings = new[]
        {
            new ListenerBinding
            {
                ListenerId = $"{instanceId}-listener",
                BindAddress = "127.0.0.1",
                Port = port,
                MaxConnections = 10,
                MaxConnectionsPerIp = 10,
            },
        },
    };

    private sealed class RdpEvidenceSink : IInteractionEventSink, ICredentialEvidenceSink
    {
        private readonly InMemoryInteractionEventSink _events = new();
        public IReadOnlyCollection<InteractionEvent> Events => _events.Events;
        public ValueTask<EventAppendResult> AppendAsync(InteractionEvent item, CancellationToken ct = default) => _events.AppendAsync(item, ct);
        public ValueTask<string> StoreAsync(CredentialEvidence evidence, CancellationToken ct = default)
            => ValueTask.FromResult(evidence.EventId);
    }

    private sealed class NoopAdapter : IHoneypotServiceAdapter
    {
        public NoopAdapter(string key) => Descriptor = new ServiceAdapterDescriptor
        {
            AdapterKey = key,
            DisplayName = key,
        };

        public ServiceAdapterDescriptor Descriptor { get; }

        public ValueTask<AdapterValidationResult> ValidateAsync(ServiceProfile profile, CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(AdapterValidationResult.Valid());

        public async ValueTask HandleAsync(
            IHoneypotSession session,
            ProtocolSessionContext context,
            ServiceProfile profile,
            IInteractionEventSink eventSink,
            CancellationToken cancellationToken = default)
        {
            await session.CloseAsync(SessionCloseReason.AdapterCompleted, cancellationToken);
        }
    }
}
