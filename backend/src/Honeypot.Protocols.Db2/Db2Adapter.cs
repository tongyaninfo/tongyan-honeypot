using System.Buffers.Binary;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Honeypot.Protocol.Abstractions.Models;
using Honeypot.Protocol.Abstractions.Service;
using Honeypot.Protocols.Common;

namespace Honeypot.Protocols.Db2;

/// <summary>Db2 LUW 的 DRDA 认证端点。只完成 EXCSAT/ACCSEC/SECCHK，永不创建数据库会话。</summary>
public sealed class Db2Adapter : ProtocolAdapterBase
{
    public override ServiceAdapterDescriptor Descriptor { get; } = new()
    {
        AdapterKey = "db2", DisplayName = "IBM Db2", SupportedFidelityLevels = ["L0", "L1", "L2", "L3"],
        SupportedClients = ["IBM JCC DRDA security mechanism 3 / 9"],
    };

    public override async ValueTask HandleAsync(IHoneypotSession session, ProtocolSessionContext context,
        ServiceProfile profile, IInteractionEventSink sink, CancellationToken cancellationToken = default)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(profile.HandshakeTimeout);
        var ct = deadline.Token;
        Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
        var ebcdic = Encoding.GetEncoding(37);
        Encoding encoding = ebcdic;
        var stage = 0;
        ushort mechanism = 0;
        string? database = null;
        byte[]? clientKey = null, serverKey = null, key = null;
        var closeReason = SessionCloseReason.AdapterCompleted;
        try
        {
            for (var messages = 0; messages < 8; messages++)
            {
                var frame = await ReadFrameAsync(session, profile.MaxFrameBytes, 6,
                    h =>
                    {
                        var length = BinaryPrimitives.ReadUInt16BigEndian(h);
                        if (length < 10 || length > profile.MaxFrameBytes) throw new InvalidDataException();
                        return length;
                    }, ct);
                if (frame is null) return;
                if (frame.Length < 10 || frame[2] != 0xd0 || (frame[3] & 15) != 1) throw new InvalidDataException();
                var correlation = BinaryPrimitives.ReadUInt16BigEndian(frame.AsSpan(4));
                var root = Objects(frame.AsSpan(6));
                if (root.Count != 1) throw new InvalidDataException();
                var command = root[0].Code;
                var values = Objects(root[0].Value);
                if (command == 0x1041 && stage == 0)
                {
                    var managers = Single(values, 0x1404) ?? [];
                    if (managers.Length % 4 != 0) throw new InvalidDataException();
                    var unicode = false;
                    for (var i = 0; i < managers.Length; i += 4)
                    {
                        var manager = BinaryPrimitives.ReadUInt16BigEndian(managers.AsSpan(i));
                        if (manager == 0x1c08) { BinaryPrimitives.WriteUInt16BigEndian(managers.AsSpan(i + 2), 1208); unicode = true; }
                    }
                    await session.WriteAsync(Reply(correlation, (frame[3] & 0x40) != 0, Object(0x1443,
                        Object(0x115e, ebcdic.GetBytes("DB2")), Object(0x1404, managers),
                        Object(0x1147, ebcdic.GetBytes("QDB2/LINUXX8664")), Object(0x116d, ebcdic.GetBytes("db2inst1")),
                        Object(0x115a, ebcdic.GetBytes("SQL11059")))), ct);
                    if (unicode) encoding = new UTF8Encoding(false, true);
                    stage = 1;
                    await sink.AppendAsync(Event(context, "HandshakeReceived", "handshake", "observed", "DRDA exchange server attributes received"), ct);
                }
                else if (command == 0x106d && stage == 1)
                {
                    mechanism = UInt16(Single(values, 0x11a2));
                    var dbBytes = Single(values, 0x2110);
                    // 首个 EXCSAT/ACCSEC 链在管理器协商应答之前已经发出，仍用初始 EBCDIC。
                    database = dbBytes is null ? null : ebcdic.GetString(dbBytes).TrimEnd();
                    if (mechanism is not (3 or 9))
                    {
                        await session.WriteAsync(Reply(correlation, false, Object(0x14ac, Object(0x11a2, Number(3), Number(9)), Object(0x11a4, [1]))), ct);
                        return;
                    }
                    if (mechanism == 9)
                    {
                        clientKey = Single(values, 0x11dc) ?? throw new InvalidDataException();
                        (serverKey, key) = Exchange(clientKey);
                    }
                    await session.WriteAsync(Reply(correlation, false, Object(0x14ac,
                        Object(0x11a2, Number(mechanism)), serverKey is null ? [] : Object(0x11dc, serverKey))), ct);
                    stage = 2;
                }
                else if (command == 0x106e && stage == 2)
                {
                    if (UInt16(Single(values, 0x11a2)) != mechanism) throw new InvalidDataException();
                    var dbBytes = Single(values, 0x2110);
                    if (dbBytes is not null) database = encoding.GetString(dbBytes).TrimEnd();
                    string username, password;
                    if (mechanism == 3)
                    {
                        username = encoding.GetString(Single(values, 0x11a0) ?? throw new InvalidDataException());
                        password = encoding.GetString(Single(values, 0x11a1) ?? throw new InvalidDataException());
                    }
                    else
                    {
                        var encrypted = values.Where(v => v.Code == 0x11dc).Select(v => v.Value).ToArray();
                        if (encrypted.Length != 2 || key is null || serverKey is null) throw new InvalidDataException();
                        username = encoding.GetString(Decrypt(encrypted[0], key, serverKey));
                        password = encoding.GetString(Decrypt(encrypted[1], key, serverKey));
                    }
                    await RecordAuthenticationAsync(sink, context, profile, username, mechanism == 3 ? "DRDA/USRIDPWD" :
                        serverKey!.Length == 64 ? "DRDA/EUSRIDPWD/AES" : "DRDA/EUSRIDPWD/DES", "SECCHKCD_0F", 1,
                        mechanism == 3 ? "Plaintext" : "Decrypted", JsonSerializer.SerializeToUtf8Bytes(new { username, password, database, securityMechanism = mechanism }), ct, database: database);
                    // SECCHKCD 0x0f 是密码无效，JCC 将其转换为认证错误；不发送 ACCRDB 成功。
                    await session.WriteAsync(Reply(correlation, false, Object(0x1219, Object(0x1149, Number(8)), Object(0x11a4, [0x0f]))), ct);
                    return;
                }
                else throw new InvalidDataException();
            }
        }
        catch (AuthenticationRecordingException) { closeReason = SessionCloseReason.StorageDegraded; throw; }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            closeReason = SessionCloseReason.HandshakeTimeout;
            await sink.AppendAsync(Event(context, "HandshakeTimeout", "handshake", "timeout", "DRDA authentication deadline exceeded"), cancellationToken);
        }
        catch (Exception ex) when (ex is InvalidDataException or DecoderFallbackException or CryptographicException or OverflowException)
        {
            closeReason = SessionCloseReason.ProtocolViolation;
            await sink.AppendAsync(Event(context, "ProtocolViolation", "handshake", "rejected", "Invalid DRDA authentication message"), cancellationToken);
        }
        catch (IOException) { closeReason = SessionCloseReason.ClientClosed; }
        catch (OperationCanceledException) { closeReason = SessionCloseReason.ListenerStopping; throw; }
        catch (Exception) { closeReason = SessionCloseReason.InternalError; throw; }
        finally
        {
            if (key is not null) CryptographicOperations.ZeroMemory(key);
            await session.CloseAsync(closeReason, CancellationToken.None);
        }
    }

    private static (byte[] Public, byte[] Key) Exchange(byte[] remote)
    {
        // DRDA 的固定 DH 参数属于线协议，不是宿主密钥。每次连接生成独立私有指数。
        var aes = remote.Length == 64;
        if (!aes && remote.Length != 32) throw new InvalidDataException();
        var prime = new BigInteger(Convert.FromHexString(aes
            ? "F24F63150EAA97CCE78F5710C45FAFBEB71CF6A8724F63140EAA97CCE78F5710C45FAFBEB71CF6A8724F631308E32B26EA1594889CBBFC91F6DF7524352EF979"
            : "C62112D73EE613F0947AB31F0F6846A1BFF5B3A4CA0D60BC1E4C7A0D8C16B3E3"), true, true);
        var generator = new BigInteger(Convert.FromHexString(aes
            ? "E8CE9E0844C67A009FB7843CD945A058935DA51B028A49E5A91F831B78364491CD0E0A8F72345DF80769549926FD16ECD6F6859481647CA9EFB2BAAC7BC09A92"
            : "4690FA1F7B9E1D4442C86C9114603FDECF071EDCEC5F626E21E256AED9EA34E4"), true, true);
        var peer = new BigInteger(remote, true, true);
        if (peer < 2 || peer >= prime - 1) throw new InvalidDataException();
        var exponent = new BigInteger(RandomNumberGenerator.GetBytes(remote.Length), true, true) % (prime - 3) + 2;
        var server = Fixed(BigInteger.ModPow(generator, exponent, prime), remote.Length);
        var secret = Fixed(BigInteger.ModPow(peer, exponent, prime), remote.Length);
        byte[] key;
        if (aes)
        {
            var first = SHA1.HashData(secret.AsSpan(0, 32));
            var last = SHA1.HashData(secret.AsSpan(32, 32));
            key = new byte[32]; first.AsSpan(0, 12).CopyTo(key); last.AsSpan(8, 12).CopyTo(key.AsSpan(20));
            for (var i = 0; i < 8; i++) key[i + 12] = (byte)(first[i + 12] ^ last[i]);
        }
        else key = secret[12..20];
        CryptographicOperations.ZeroMemory(secret);
        return (server, key);
    }

    private static byte[] Decrypt(byte[] cipherText, byte[] key, byte[] serverPublic)
    {
        using SymmetricAlgorithm cipher = serverPublic.Length == 64 ? Aes.Create() : DES.Create();
        cipher.Key = key;
        var iv = serverPublic.Length == 64 ? serverPublic[24..40] : serverPublic[12..20];
        return cipher.DecryptCbc(cipherText, iv, PaddingMode.PKCS7);
    }

    private static byte[] Fixed(BigInteger value, int length)
    {
        var bytes = value.ToByteArray(true, true);
        if (bytes.Length > length) throw new InvalidDataException();
        var result = new byte[length]; bytes.CopyTo(result, length - bytes.Length); return result;
    }

    private static List<(ushort Code, byte[] Value)> Objects(ReadOnlySpan<byte> data)
    {
        var result = new List<(ushort, byte[])>();
        while (data.Length > 0)
        {
            if (data.Length < 4) throw new InvalidDataException();
            var length = BinaryPrimitives.ReadUInt16BigEndian(data);
            if (length < 4 || length > data.Length || result.Count >= 128) throw new InvalidDataException();
            result.Add((BinaryPrimitives.ReadUInt16BigEndian(data[2..]), data[4..length].ToArray()));
            data = data[length..];
        }
        return result;
    }
    private static byte[]? Single(List<(ushort Code, byte[] Value)> values, ushort code)
    {
        var matches = values.Where(v => v.Code == code).ToArray();
        if (matches.Length > 1) throw new InvalidDataException();
        return matches.Length == 0 ? null : matches[0].Value;
    }
    private static ushort UInt16(byte[]? value) => value is { Length: 2 } ? BinaryPrimitives.ReadUInt16BigEndian(value) : throw new InvalidDataException();
    private static byte[] Number(ushort value) { var bytes = new byte[2]; BinaryPrimitives.WriteUInt16BigEndian(bytes, value); return bytes; }
    private static byte[] Object(ushort code, params byte[][] values)
    {
        var result = new byte[4 + values.Sum(v => v.Length)];
        BinaryPrimitives.WriteUInt16BigEndian(result, checked((ushort)result.Length));
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(2), code);
        var offset = 4; foreach (var value in values) { value.CopyTo(result, offset); offset += value.Length; }
        return result;
    }
    private static byte[] Reply(ushort correlation, bool chained, byte[] value)
    {
        var result = new byte[6 + value.Length];
        BinaryPrimitives.WriteUInt16BigEndian(result, checked((ushort)result.Length));
        result[2] = 0xd0; result[3] = chained ? (byte)0x42 : (byte)2;
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(4), correlation);
        value.CopyTo(result, 6); return result;
    }
}
