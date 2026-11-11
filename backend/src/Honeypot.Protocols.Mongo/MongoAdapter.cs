using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Honeypot.Protocol.Abstractions.Models;
using Honeypot.Protocol.Abstractions.Service;
using Honeypot.Protocols.Common;
using Honeypot.Protocols.Mongo.Common;

namespace Honeypot.Protocols.Mongo;

/// <summary>仅实现 MongoDB 握手和失败认证，SCRAM 记录 proof，不将其伪称为密码。</summary>
public sealed class MongoAdapter : ProtocolAdapterBase
{
    private static readonly UTF8Encoding Utf8 = new(false, true);
    public override ServiceAdapterDescriptor Descriptor => new()
    {
        AdapterKey = "mongodb", DisplayName = "MongoDB", Version = "1", SupportedTransports = ["tcp"],
        SupportedFidelityLevels = ["L1", "L2", "L3"], SupportedClients = ["mongosh", "MongoDB.Driver"],
    };

    public override async ValueTask HandleAsync(IHoneypotSession session, ProtocolSessionContext context,
        ServiceProfile profile, IInteractionEventSink sink, CancellationToken cancellationToken = default)
    {
        var reason = SessionCloseReason.AdapterCompleted;
        ScramConversation? conversation = null;
        var recorded = false;
        var bytes = 0L;
        var connectionId = RandomNumberGenerator.GetInt32(1, int.MaxValue);
        try
        {
            // 监控连接允许继续 hello；所有请求仍受数量、字节和每轮总时限约束。
            for (var exchange = 0; exchange < 64; exchange++)
            {
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                timeout.CancelAfter(conversation is null && exchange > 0 ? profile.IdleTimeout : profile.HandshakeTimeout);
                var ct = timeout.Token;
                var frame = await ReadMessageAsync(session, Math.Min(profile.MaxFrameBytes, 65536), ct);
                bytes += frame.Length;
                if (bytes > profile.MaxSessionBytes) throw new InvalidDataException();
                var message = ParseMessage(frame);
                var command = message.Document.FirstOrDefault().Key;
                if (command is null) throw new InvalidDataException();
                Dictionary<string, object?> reply;
                var close = false;
                try
                {
                if (command is "hello" or "isMaster" or "ismaster")
                {
                    await sink.AppendAsync(Event(context, "HandshakeReceived", "handshake", "observed", "MongoDB hello"), ct);
                    reply = Hello(profile, connectionId);
                    if (message.Document.ContainsKey("saslSupportedMechs"))
                        reply["saslSupportedMechs"] = new[] { "SCRAM-SHA-256", "SCRAM-SHA-1" };
                    if (message.Document.TryGetValue("speculativeAuthenticate", out var speculative) && speculative is Dictionary<string, object?> auth)
                    {
                        if (conversation is not null) throw new InvalidDataException();
                        // speculativeAuthenticate 只影响嵌套认证结果，不能把整个 hello 当密码错误。
                        if (Text(auth, "mechanism") is "SCRAM-SHA-256" or "SCRAM-SHA-1")
                        {
                            conversation = StartScram(auth, Text(auth, "db") ?? Text(message.Document, "$db") ?? "admin");
                            reply["speculativeAuthenticate"] = Challenge(conversation);
                        }
                    }
                }
                else if (command is "buildInfo" or "buildinfo")
                {
                    reply = new() { ["version"] = ProtocolFingerprint.Version(profile), ["ok"] = 1.0 };
                }
                else if (command == "saslStart")
                {
                    if (conversation is not null) throw new InvalidDataException();
                    var method = Text(message.Document, "mechanism") ?? "unknown";
                    var database = Text(message.Document, "$db") ?? "admin";
                    if (method is "SCRAM-SHA-1" or "SCRAM-SHA-256")
                    {
                        conversation = StartScram(message.Document, database);
                        reply = Challenge(conversation);
                    }
                    else
                    {
                        var payload = Payload(message.Document);
                        string? username = null, password = null;
                        if (method == "PLAIN") (username, password) = ParsePlain(payload);
                        var material = JsonSerializer.SerializeToUtf8Bytes(new { username, password, database, method, payload = Convert.ToBase64String(payload) });
                        try
                        {
                            await RecordAuthenticationAsync(sink, context, profile, username, method, "18", 1,
                                method == "PLAIN" ? "Plaintext" : "Response", material, ct, database: database);
                            recorded = true;
                        }
                        finally { CryptographicOperations.ZeroMemory(material); }
                        reply = AuthenticationError(); close = true;
                    }
                }
                else if (command == "saslContinue")
                {
                    var final = Payload(message.Document);
                    recorded = true;
                    if (conversation is null)
                    {
                        var material = JsonSerializer.SerializeToUtf8Bytes(new { payload = Convert.ToBase64String(final), invalidConversation = true });
                        try { await RecordAuthenticationAsync(sink, context, profile, null, "unknown", "18", 1, "Response", material, ct); }
                        finally { CryptographicOperations.ZeroMemory(material); }
                    }
                    else
                    {
                        var valid = message.Document.TryGetValue("conversationId", out var id) && id is int number && number == conversation.Id &&
                                    (Text(message.Document, "$db") ?? "admin") == conversation.Database && ValidFinal(conversation, final);
                        await RecordScramAsync(sink, context, profile, conversation, final, valid ? "client-proof" : "invalid-client-final", ct);
                    }
                    reply = AuthenticationError(); close = true;
                }
                else if (command == "authenticate")
                {
                    var username = Text(message.Document, "user");
                    var method = Text(message.Document, "mechanism") ?? "MONGODB-CR";
                    var database = Text(message.Document, "$db") ?? "admin";
                    var material = JsonSerializer.SerializeToUtf8Bytes(new { username, database, method, command = Convert.ToBase64String(frame) });
                    try { await RecordAuthenticationAsync(sink, context, profile, username, method, "18", 1, "Response", material, ct, database: database); }
                    finally { CryptographicOperations.ZeroMemory(material); }
                    recorded = true; reply = AuthenticationError(); close = true;
                }
                else reply = Error(13, "Unauthorized", "Command requires authentication");
                }
                catch (Exception ex) when ((ex is InvalidDataException or DecoderFallbackException or FormatException) &&
                                           command is "saslStart" or "saslContinue" or "authenticate")
                {
                    // 外层命令合法但认证字段损坏时，保留收到的原始材料并返回认证错误。
                    // 不能因无法解码密码而把它写入异常信息或直接丢弃取证。
                    recorded = true;
                    var method = Text(message.Document, "mechanism") ?? conversation?.Method ?? "unknown";
                    var database = Text(message.Document, "$db") ?? conversation?.Database ?? "admin";
                    var username = conversation?.Username ?? Text(message.Document, "user");
                    var material = JsonSerializer.SerializeToUtf8Bytes(new
                    {
                        username, database, method, stage = "malformed-authentication", command = Convert.ToBase64String(frame),
                    });
                    try { await RecordAuthenticationAsync(sink, context, profile, username, method, "18", 1, "Response", material, ct, database: database); }
                    finally { CryptographicOperations.ZeroMemory(material); }
                    reply = AuthenticationError(); close = true;
                }
                var response = BuildResponse(message, reply);
                bytes += response.Length;
                if (bytes > profile.MaxSessionBytes) throw new InvalidDataException();
                await session.WriteAsync(response, ct);
                if (close) return;
            }
            reason = SessionCloseReason.ProtocolViolation;
        }
        catch (AuthenticationRecordingException) { reason = SessionCloseReason.StorageDegraded; throw; }
        catch (EndOfStreamException)
        {
            reason = SessionCloseReason.ClientClosed;
            await RecordIncompleteScramAsync("client-closed-before-proof");
        }
        catch (Exception ex) when (ex is InvalidDataException or DecoderFallbackException or FormatException)
        {
            reason = SessionCloseReason.ProtocolViolation;
            await RecordIncompleteScramAsync("invalid-frame-before-proof");
            await sink.AppendAsync(Event(context, "ProtocolViolation", "authentication", "rejected", "invalid MongoDB message or authentication state"), cancellationToken);
        }
        catch (IOException)
        {
            reason = SessionCloseReason.ClientClosed;
            await RecordIncompleteScramAsync("transport-closed-before-proof");
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            reason = SessionCloseReason.HandshakeTimeout;
            await RecordIncompleteScramAsync("timeout-before-proof");
            await sink.AppendAsync(Event(context, "ProtocolViolation", "authentication", "timeout", "MongoDB authentication timeout"), cancellationToken);
        }
        catch (OperationCanceledException) { reason = SessionCloseReason.ListenerStopping; throw; }
        catch (Exception) { reason = SessionCloseReason.InternalError; throw; }
        finally { await session.CloseAsync(reason, CancellationToken.None); }

        async ValueTask RecordIncompleteScramAsync(string stage)
        {
            if (conversation is null || recorded || cancellationToken.IsCancellationRequested) return;
            recorded = true;
            using var evidenceTimeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            evidenceTimeout.CancelAfter(TimeSpan.FromSeconds(3));
            await RecordScramAsync(sink, context, profile, conversation, null, stage, evidenceTimeout.Token);
        }
    }

    private sealed record ScramConversation(int Id, string Username, string Database, string Method, string ClientFirst, string Header, string Nonce, string ServerFirst);

    private static ScramConversation StartScram(Dictionary<string, object?> auth, string database)
    {
        var method = Text(auth, "mechanism") ?? throw new InvalidDataException();
        var first = Utf8.GetString(Payload(auth));
        if (!(first.StartsWith("n,,", StringComparison.Ordinal) || first.StartsWith("y,,", StringComparison.Ordinal))) throw new InvalidDataException();
        var attributes = Attributes(first[3..]);
        if (attributes.Count != 2 || !attributes.TryGetValue('n', out var user) || !attributes.TryGetValue('r', out var nonce) ||
            nonce.Length is < 1 or > 1024 || nonce.Any(x => x < 0x21 || x > 0x7e)) throw new InvalidDataException();
        var username = DecodeUsername(user);
        var serverNonce = nonce + Convert.ToBase64String(RandomNumberGenerator.GetBytes(18));
        var salt = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));
        var iterations = method == "SCRAM-SHA-256" ? 15000 : 10000;
        var serverFirst = $"r={serverNonce},s={salt},i={iterations}";
        return new ScramConversation(RandomNumberGenerator.GetInt32(1, int.MaxValue), username, database, method, first, first[..3], serverNonce, serverFirst);
    }

    private static Dictionary<char, string> Attributes(string text)
    {
        var attributes = new Dictionary<char, string>();
        foreach (var part in text.Split(','))
        {
            if (part.Length < 2 || part[1] != '=' || !attributes.TryAdd(part[0], part[2..])) throw new InvalidDataException();
        }
        return attributes;
    }

    private static string DecodeUsername(string encoded)
    {
        var builder = new StringBuilder();
        for (var i = 0; i < encoded.Length; i++)
        {
            if (encoded[i] != '=') { builder.Append(encoded[i]); continue; }
            if (i + 2 >= encoded.Length) throw new InvalidDataException();
            builder.Append(encoded.Substring(i + 1, 2) switch { "2C" => ',', "3D" => '=', _ => throw new InvalidDataException() }); i += 2;
        }
        return builder.ToString();
    }

    private static bool ValidFinal(ScramConversation conversation, byte[] payload)
    {
        try
        {
            var attributes = Attributes(Utf8.GetString(payload));
            return attributes.Count == 3 && attributes.GetValueOrDefault('r') == conversation.Nonce &&
                   attributes.TryGetValue('c', out var binding) && Utf8.GetString(Convert.FromBase64String(binding)) == conversation.Header &&
                   attributes.TryGetValue('p', out var proof) && Convert.FromBase64String(proof).Length == (conversation.Method == "SCRAM-SHA-256" ? 32 : 20);
        }
        catch (Exception ex) when (ex is InvalidDataException or FormatException or DecoderFallbackException) { return false; }
    }

    private static (string Username, string Password) ParsePlain(byte[] payload)
    {
        var first = Array.IndexOf(payload, (byte)0);
        var second = first < 0 ? -1 : Array.IndexOf(payload, (byte)0, first + 1);
        if (first < 0 || second < 0 || payload.AsSpan(second + 1).Contains((byte)0)) throw new InvalidDataException();
        return (Utf8.GetString(payload.AsSpan(first + 1, second - first - 1)), Utf8.GetString(payload.AsSpan(second + 1)));
    }

    private static async ValueTask RecordScramAsync(IInteractionEventSink sink, ProtocolSessionContext context, ServiceProfile profile,
        ScramConversation conversation, byte[]? final, string stage, CancellationToken ct)
    {
        var material = JsonSerializer.SerializeToUtf8Bytes(new
        {
            username = conversation.Username, database = conversation.Database, method = conversation.Method,
            conversationId = conversation.Id, clientFirst = conversation.ClientFirst, serverFirst = conversation.ServerFirst,
            clientFinal = final is null ? null : Convert.ToBase64String(final), stage,
        });
        try { await RecordAuthenticationAsync(sink, context, profile, conversation.Username, conversation.Method, "18", 1, "Response", material, ct, database: conversation.Database); }
        finally { CryptographicOperations.ZeroMemory(material); }
    }

    private static Dictionary<string, object?> Challenge(ScramConversation conversation) => new()
    {
        ["conversationId"] = conversation.Id, ["done"] = false,
        ["payload"] = new MongoBson.Binary(Utf8.GetBytes(conversation.ServerFirst)), ["ok"] = 1.0,
    };
    private static Dictionary<string, object?> Hello(ServiceProfile profile, int connectionId) => new()
    {
        ["isWritablePrimary"] = true, ["ismaster"] = true, ["helloOk"] = true, ["minWireVersion"] = 0, ["maxWireVersion"] = 21,
        ["maxBsonObjectSize"] = Math.Max(5, Math.Min(profile.MaxFrameBytes, 65536) - 64),
        ["maxMessageSizeBytes"] = Math.Min(profile.MaxFrameBytes, 65536), ["maxWriteBatchSize"] = 1000,
        ["connectionId"] = connectionId, ["me"] = ProtocolFingerprint.HostName(profile), ["ok"] = 1.0,
    };
    private static Dictionary<string, object?> AuthenticationError() => Error(18, "AuthenticationFailed", "Authentication failed.");
    private static Dictionary<string, object?> Error(int code, string name, string message) => new()
    { ["ok"] = 0.0, ["errmsg"] = message, ["code"] = code, ["codeName"] = name };
    private static string? Text(Dictionary<string, object?> doc, string key) => doc.TryGetValue(key, out var value) ? value as string : null;
    private static byte[] Payload(Dictionary<string, object?> doc) => doc.TryGetValue("payload", out var value) && value is MongoBson.Binary { Subtype: 0 } binary ? binary.Data : throw new InvalidDataException();
    private sealed record Message(int RequestId, int Opcode, Dictionary<string, object?> Document);

    private static async ValueTask<byte[]> ReadMessageAsync(IHoneypotSession session, int maximum, CancellationToken ct)
    {
        var header = new byte[4]; await ExactAsync(session, header, ct);
        var length = BinaryPrimitives.ReadInt32LittleEndian(header);
        if (length < 21 || length > maximum) throw new InvalidDataException();
        var frame = new byte[length]; header.CopyTo(frame, 0); await ExactAsync(session, frame.AsMemory(4), ct); return frame;
    }
    private static async ValueTask ExactAsync(IHoneypotSession session, Memory<byte> buffer, CancellationToken ct)
    {
        var offset = 0;
        while (offset < buffer.Length)
        {
            var count = await session.ReadAsync(buffer[offset..], ct); if (count == 0) throw new EndOfStreamException(); offset += count;
        }
    }

    private static Message ParseMessage(byte[] frame)
    {
        if (BinaryPrimitives.ReadInt32LittleEndian(frame.AsSpan(8)) != 0) throw new InvalidDataException();
        var opcode = BinaryPrimitives.ReadInt32LittleEndian(frame.AsSpan(12));
        var offset = 20;
        Dictionary<string, object?>? document = null;
        if (opcode == 2013)
        {
            var flags = BinaryPrimitives.ReadUInt32LittleEndian(frame.AsSpan(16));
            // 不提供 exhaust 或无响应写命令；未知 required flags 拒绝。
            if ((flags & 0x0000fffe) != 0) throw new InvalidDataException();
            var end = frame.Length;
            if ((flags & 1) != 0)
            {
                end -= 4;
                if (end < 21 || BinaryPrimitives.ReadUInt32LittleEndian(frame.AsSpan(end)) != Crc32C(frame.AsSpan(0, end))) throw new InvalidDataException();
            }
            while (offset < end)
            {
                var kind = frame[offset++];
                if (kind != 0 || document is not null) throw new InvalidDataException();
                document = MongoBson.Decode(frame.AsSpan(offset, end - offset), out var consumed); offset += consumed;
            }
            if (offset != end) throw new InvalidDataException();
        }
        else if (opcode == 2004)
        {
            // 驱动的旧式握手可携带 secondaryOk，其他查询模式不在认证适配范围。
            if ((BinaryPrimitives.ReadInt32LittleEndian(frame.AsSpan(16)) & ~4) != 0) throw new InvalidDataException();
            var name = MongoBson.CString(frame, ref offset);
            if (!name.EndsWith(".$cmd", StringComparison.Ordinal) || frame.Length - offset < 13) throw new InvalidDataException();
            if (BinaryPrimitives.ReadInt32LittleEndian(frame.AsSpan(offset)) != 0) throw new InvalidDataException();
            offset += 8;
            document = MongoBson.Decode(frame.AsSpan(offset), out var consumed); offset += consumed;
            if (offset != frame.Length) throw new InvalidDataException();
            // 部分官方驱动在初始认证期间仍用 OP_QUERY；数据库来自命令命名空间。
            // 同样只运行上面的握手/认证白名单，不提供查询或写入功能。
            if (!document.ContainsKey("$db")) document["$db"] = name[..^5];
        }
        else throw new InvalidDataException();
        return new Message(BinaryPrimitives.ReadInt32LittleEndian(frame.AsSpan(4)), opcode, document ?? throw new InvalidDataException());
    }

    private static byte[] BuildResponse(Message message, Dictionary<string, object?> document)
    {
        var bson = MongoBson.Encode(document);
        var offset = message.Opcode == 2004 ? 36 : 21;
        var packet = new byte[offset + bson.Length];
        BinaryPrimitives.WriteInt32LittleEndian(packet, packet.Length);
        BinaryPrimitives.WriteInt32LittleEndian(packet.AsSpan(4), unchecked(message.RequestId + 1));
        BinaryPrimitives.WriteInt32LittleEndian(packet.AsSpan(8), message.RequestId);
        BinaryPrimitives.WriteInt32LittleEndian(packet.AsSpan(12), message.Opcode == 2004 ? 1 : 2013);
        if (message.Opcode == 2004) BinaryPrimitives.WriteInt32LittleEndian(packet.AsSpan(32), 1);
        bson.CopyTo(packet, offset); return packet;
    }
    private static uint Crc32C(ReadOnlySpan<byte> data)
    {
        var crc = uint.MaxValue;
        foreach (var value in data)
        {
            crc ^= value;
            for (var bit = 0; bit < 8; bit++) crc = (crc >> 1) ^ ((crc & 1) == 0 ? 0u : 0x82f63b78u);
        }
        return ~crc;
    }
}
