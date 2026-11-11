using System.Security.Cryptography;

namespace Honeypot.Protocols.Nfs.Common;

/// <summary>仅保留一次连接的 v4.1 协商状态；根标识为随机值，不对应宿主文件或真实导出目录。</summary>
internal sealed class NfsCompound(string serverName, int maximum)
{
    private readonly ulong _clientId = BitConverter.ToUInt64(RandomNumberGenerator.GetBytes(8)) | 1UL;
    private readonly byte[] _sessionId = RandomNumberGenerator.GetBytes(16);
    private readonly byte[] _rootHandle = RandomNumberGenerator.GetBytes(16);
    private bool _exchanged, _created;
    private uint _lastSequence;
    private byte[]? _lastRequest, _lastReply;

    public (byte[] Body, bool AccessDenied, uint? Operation, string? Path) Process(byte[] args)
    {
        var reader = new XdrReader(args);
        var tag = reader.Opaque(1024); var minor = reader.UInt(); var count = reader.UInt();
        if (minor != 1) return (Reply(tag, 10021, []), false, null, null); // NFS4ERR_MINOR_VERS_MISMATCH
        if (count > 64) return (Reply(tag, 10070, []), false, null, null); // NFS4ERR_TOO_MANY_OPS
        if (_lastRequest is not null && args.AsSpan().SequenceEqual(_lastRequest)) return (_lastReply!, false, null, null);
        var output = new List<byte[]>();
        var status = 0u; var denied = false; uint? deniedOperation = null; string? path = null;
        var inSession = false; var currentHandle = false;
        for (var index = 0; index < count; index++)
        {
            var operation = reader.UInt();
            var result = new XdrWriter(); result.UInt(operation);
            if (index == 0 && operation is not (42 or 43 or 53 or 41 or 44 or 45 or 57))
            {
                status = 10071; result.UInt(status); output.Add(result.Bytes()); break; // OP_NOT_IN_SESSION
            }
            switch (operation)
            {
                case 42: // EXCHANGE_ID：只交换标识，不授权文件访问。
                {
                    if (count != 1) { status = 10081; result.UInt(status); break; } // NOT_ONLY_OP
                    reader.Fixed(8); reader.Opaque(1024); reader.UInt();
                    var protection = reader.UInt();
                    if (protection != 0) { status = 22; result.UInt(status); break; } // AUTH_SYS 不能要求 MACH_CRED/SSV。
                    var implementations = reader.UInt(); if (implementations > 1) throw new InvalidDataException("Invalid implementation list.");
                    for (var i = 0; i < implementations; i++) { reader.Opaque(1024); reader.Opaque(1024); reader.ULong(); reader.UInt(); }
                    _exchanged = true;
                    result.UInt(0); result.ULong(_clientId); result.UInt(1); result.UInt(0x10000); result.UInt(0);
                    result.ULong(0); result.Text(serverName); result.Text(serverName); result.UInt(0);
                    break;
                }
                case 43: // CREATE_SESSION：限定单 slot、单连接的短暂协议状态，不创建文件会话。
                {
                    if (count != 1) { status = 10081; result.UInt(status); break; }
                    var clientId = reader.ULong(); var sequence = reader.UInt(); reader.UInt();
                    var fore = ReadChannel(reader); var back = ReadChannel(reader); reader.UInt();
                    var securityCount = reader.UInt(); if (securityCount > 8) throw new InvalidDataException("Invalid callback security.");
                    for (var i = 0; i < securityCount; i++)
                    {
                        switch (reader.UInt())
                        {
                            case 0: break;
                            case 1: reader.UInt(); reader.Opaque(255); reader.UInt(); reader.UInt(); reader.Array(16); break;
                            case 6: reader.UInt(); reader.Opaque(400); reader.Opaque(400); break;
                            default: throw new InvalidDataException("Invalid callback authentication flavor.");
                        }
                    }
                    if (!_exchanged || clientId != _clientId) { status = 10022; result.UInt(status); break; }
                    if (sequence != 1 || _created) { status = 10063; result.UInt(status); break; }
                    if (fore[1] < 256 || fore[2] < 256 || fore[4] < 2 || fore[5] == 0) { status = 10005; result.UInt(status); break; }
                    _created = true;
                    result.UInt(0); result.Fixed(_sessionId); result.UInt(sequence); result.UInt(0);
                    WriteChannel(result, fore); WriteChannel(result, back);
                    break;
                }
                case 53: // SEQUENCE
                {
                    var session = reader.Fixed(16); var sequence = reader.UInt(); var slot = reader.UInt(); reader.UInt(); var cache = reader.UInt();
                    if (cache > 1) throw new InvalidDataException("Invalid XDR boolean.");
                    if (index != 0) { status = 10064; result.UInt(status); break; }
                    if (!_created || !session.AsSpan().SequenceEqual(_sessionId)) { status = 10052; result.UInt(status); break; }
                    if (slot != 0) { status = 10053; result.UInt(status); break; }
                    if (sequence != _lastSequence + 1) { status = 10063; result.UInt(status); break; }
                    _lastSequence = sequence; inSession = true;
                    result.UInt(0); result.Fixed(_sessionId); result.UInt(sequence); result.UInt(0); result.UInt(0); result.UInt(0); result.UInt(0);
                    break;
                }
                case 24: // PUTROOTFH：只设置内存中的虚拟根标识。
                    if (!inSession) { status = 10071; result.UInt(status); break; }
                    currentHandle = true; result.UInt(0); break;
                case 22: // PUTFH
                    var handle = reader.Opaque(128);
                    status = !inSession ? 10071u : handle.AsSpan().SequenceEqual(_rootHandle) ? 0u : 10001u;
                    currentHandle = status == 0; result.UInt(status); break;
                case 10: // GETFH：不含路径或目录内容。
                    status = !currentHandle ? 10020u : 0;
                    result.UInt(status); if (status == 0) result.Opaque(_rootHandle); break;
                case 9: // GETATTR
                    reader.Array(8); goto case 16;
                case 15: // LOOKUP
                    path = reader.Text(1024); goto case 16;
                case 3: // ACCESS
                    reader.UInt(); goto case 16;
                case 16: // LOOKUPP：按 RFC 8881 对支持 ACCESS 错误的操作拒绝。
                    status = !currentHandle ? 10020u : 13u;
                    result.UInt(status);
                    denied = status == 13; deniedOperation = denied ? operation : null;
                    break;
                case 44: // DESTROY_SESSION
                    var destroy = reader.Fixed(16);
                    status = _created && destroy.AsSpan().SequenceEqual(_sessionId) ? 0u : 10052u;
                    if (status == 0) _created = false;
                    result.UInt(status); break;
                default:
                    // 未实现操作返回合法 OP_ILLEGAL，不假装完整文件服务。
                    result = new XdrWriter(); result.UInt(10044); status = 10044; result.UInt(status); break;
            }
            output.Add(result.Bytes());
            if (status != 0) break;
        }
        if (status == 0) reader.End();
        var reply = Reply(tag, status, output);
        if (inSession) { _lastRequest = args; _lastReply = reply; }
        return (reply, denied, deniedOperation, path);
    }

    private static uint[] ReadChannel(XdrReader reader)
    {
        var values = new uint[6]; for (var i = 0; i < values.Length; i++) values[i] = reader.UInt();
        reader.Array(1); return values;
    }
    private void WriteChannel(XdrWriter writer, uint[] requested)
    {
        writer.UInt(0); writer.UInt(Math.Min(requested[1], (uint)maximum)); writer.UInt(Math.Min(requested[2], (uint)maximum));
        writer.UInt(Math.Min(requested[3], (uint)maximum)); writer.UInt(Math.Min(requested[4], 64)); writer.UInt(1); writer.UInt(0);
    }
    private static byte[] Reply(byte[] tag, uint status, IReadOnlyCollection<byte[]> results)
    {
        var writer = new XdrWriter(); writer.UInt(status); writer.Opaque(tag); writer.UInt((uint)results.Count);
        foreach (var result in results) writer.Fixed(result);
        return writer.Bytes();
    }
}
