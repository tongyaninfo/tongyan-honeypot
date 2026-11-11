using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Honeypot.Protocols.Smb.Common;

/// <summary>SMB2/3 认证阶段报文；长度/偏移均相对 SMB2 头校验，禁止复合请求越界。</summary>
internal static class SmbProtocol
{
    public const uint LogonFailure = 0xC000006D;
    public const uint MoreProcessing = 0xC0000016;
    public static ushort U16(ReadOnlySpan<byte> bytes, int offset) => BinaryPrimitives.ReadUInt16LittleEndian(bytes[offset..]);
    public static uint U32(ReadOnlySpan<byte> bytes, int offset) => BinaryPrimitives.ReadUInt32LittleEndian(bytes[offset..]);
    public static ulong U64(ReadOnlySpan<byte> bytes, int offset) => BinaryPrimitives.ReadUInt64LittleEndian(bytes[offset..]);
    private static void W16(Span<byte> bytes, int offset, ushort value) => BinaryPrimitives.WriteUInt16LittleEndian(bytes[offset..], value);
    private static void W32(Span<byte> bytes, int offset, uint value) => BinaryPrimitives.WriteUInt32LittleEndian(bytes[offset..], value);
    private static void W64(Span<byte> bytes, int offset, ulong value) => BinaryPrimitives.WriteUInt64LittleEndian(bytes[offset..], value);

    public static ushort Command(byte[] packet)
    {
        if (packet.Length < 64 || !packet.AsSpan(0, 4).SequenceEqual(new byte[] { 0xFE, 0x53, 0x4D, 0x42 }) ||
            U16(packet, 4) != 64 || (U32(packet, 16) & 3) != 0 || U32(packet, 20) != 0)
            throw new InvalidDataException("Invalid SMB2 header.");
        return U16(packet, 12);
    }

    public static ushort SelectDialect(byte[] request)
    {
        if (request.Length < 102 || U16(request, 64) != 36) throw new InvalidDataException("Invalid SMB negotiate.");
        var count = U16(request, 66);
        if (count is 0 or > 128 || 100 + count * 2 > request.Length) throw new InvalidDataException("Invalid dialect array.");
        var dialects = new HashSet<ushort>();
        for (var index = 0; index < count; index++) dialects.Add(U16(request, 100 + index * 2));
        foreach (ushort dialect in new ushort[] { 0x0311, 0x0302, 0x0300, 0x0210, 0x0202 })
        {
            if (!dialects.Contains(dialect)) continue;
            if (dialect == 0x0311) ValidatePreauthContext(request, 100 + count * 2);
            return dialect;
        }
        throw new InvalidDataException("Unsupported SMB dialect.");
    }

    private static void ValidatePreauthContext(byte[] request, int dialectEnd)
    {
        var offsetValue = U32(request, 92);
        if (offsetValue > int.MaxValue || offsetValue < dialectEnd || offsetValue % 8 != 0) throw new InvalidDataException("Invalid negotiate context offset.");
        var offset = (int)offsetValue;
        var count = U16(request, 96);
        if (count is 0 or > 32) throw new InvalidDataException("Invalid negotiate contexts.");
        var found = false;
        var seen = new HashSet<ushort>();
        for (var index = 0; index < count; index++)
        {
            if (offset > request.Length - 8) throw new InvalidDataException("Truncated negotiate context.");
            var type = U16(request, offset);
            var length = U16(request, offset + 2);
            if (length > request.Length - offset - 8 || !seen.Add(type)) throw new InvalidDataException("Invalid negotiate context.");
            if (type == 1)
            {
                if (length < 6) throw new InvalidDataException("Invalid preauthentication capabilities.");
                var hashes = U16(request, offset + 8); var salt = U16(request, offset + 10);
                if (hashes == 0 || 4 + hashes * 2 + salt != length) throw new InvalidDataException("Invalid preauthentication hash list.");
                for (var h = 0; h < hashes; h++) found |= U16(request, offset + 12 + h * 2) == 1;
            }
            offset = (offset + 8 + length + 7) & ~7;
        }
        if (!found) throw new InvalidDataException("SMB 3.1.1 requires SHA-512 preauthentication integrity.");
    }

    public static byte[] NegotiateResponse(byte[] request, ushort dialect, byte[] serverGuid, DateTimeOffset startedAt, int maxBytes)
    {
        var token = SmbSpnego.NegotiateToken();
        var contextOffset = (128 + token.Length + 7) & ~7;
        var response = Header(request, 0, 0, dialect == 0x0311 ? contextOffset + 46 : 128 + token.Length);
        W16(response, 64, 65); W16(response, 66, 1); W16(response, 68, dialect);
        serverGuid.CopyTo(response, 72);
        // 认证永远失败，不宣告共享、加密通道、多通道或目录租约等业务能力。
        W32(response, 92, (uint)Math.Min(maxBytes, 65536));
        W32(response, 96, (uint)Math.Min(maxBytes, 65536));
        W32(response, 100, (uint)Math.Min(maxBytes, 65536));
        W64(response, 104, (ulong)DateTimeOffset.UtcNow.ToFileTime());
        W64(response, 112, (ulong)startedAt.ToFileTime());
        W16(response, 120, 128); W16(response, 122, (ushort)token.Length);
        token.CopyTo(response, 128);
        if (dialect == 0x0311)
        {
            W16(response, 70, 1); W32(response, 124, (uint)contextOffset);
            W16(response, contextOffset, 1); W16(response, contextOffset + 2, 38);
            W16(response, contextOffset + 8, 1); W16(response, contextOffset + 10, 32);
            W16(response, contextOffset + 12, 1);
            RandomNumberGenerator.Fill(response.AsSpan(contextOffset + 14, 32));
        }
        return response;
    }

    public static byte[] SecurityToken(byte[] request)
    {
        if (request.Length < 88 || U16(request, 64) != 25 || (request[66] & 1) != 0)
            throw new InvalidDataException("Invalid session setup.");
        var offset = U16(request, 76); var length = U16(request, 78);
        if (length == 0 || offset < 88 || offset > request.Length || length > request.Length - offset)
            throw new InvalidDataException("Invalid security buffer.");
        return request.AsSpan(offset, length).ToArray();
    }

    public static byte[] SessionChallenge(byte[] request, byte[] token, ulong sessionId)
    {
        var response = Header(request, MoreProcessing, sessionId, 72 + token.Length);
        W16(response, 64, 9); W16(response, 68, 72); W16(response, 70, checked((ushort)token.Length));
        token.CopyTo(response, 72);
        return response;
    }

    public static byte[] Error(byte[] request, uint status, ulong sessionId)
    {
        var response = Header(request, status, sessionId, 73);
        W16(response, 64, 9);
        return response;
    }

    private static byte[] Header(byte[] request, uint status, ulong sessionId, int length)
    {
        var response = new byte[length];
        new byte[] { 0xFE, 0x53, 0x4D, 0x42 }.CopyTo(response, 0);
        W16(response, 4, 64); W16(response, 6, U16(request, 6)); W32(response, 8, status);
        W16(response, 12, U16(request, 12)); W16(response, 14, Math.Max((ushort)1, Math.Min(U16(request, 14), (ushort)32)));
        W32(response, 16, 1); W64(response, 24, U64(request, 24)); W32(response, 32, U32(request, 32));
        W64(response, 40, sessionId);
        return response;
    }

    public static byte[] Hash(byte[] previous, byte[] packet)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA512);
        hash.AppendData(previous); hash.AppendData(packet);
        return hash.GetHashAndReset();
    }
}
