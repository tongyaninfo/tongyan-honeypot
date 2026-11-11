using System.Formats.Asn1;
using Honeypot.Protocols.Common;

namespace Honeypot.Protocols.Rdp;

/// <summary>只处理 CredSSP/SPNEGO 认证交换，不进入成功后的凭据委派或桌面阶段。</summary>
internal static class CredSspProtocol
{
    private const string NtlmOid = "1.3.6.1.4.1.311.2.2.10";

    internal readonly record struct Request(int Version, byte[]? NegoToken);

    public static bool TryReadRequest(ReadOnlyMemory<byte> bytes, out Request request)
    {
        request = default;
        try
        {
            var outer = new AsnReader(bytes, AsnEncodingRules.DER);
            var sequence = outer.ReadSequence();
            outer.ThrowIfNotEmpty();
            var versionField = sequence.ReadSequence(Tag(0));
            if (!versionField.TryReadInt32(out var version) || version < 2) return false;
            versionField.ThrowIfNotEmpty();
            byte[]? token = null;
            var previousTag = 0;
            while (sequence.HasData)
            {
                var tag = sequence.PeekTag();
                if (tag.TagClass != TagClass.ContextSpecific || tag.TagValue <= previousTag || tag.TagValue > 5) return false;
                previousTag = tag.TagValue;
                var field = sequence.ReadSequence(Tag(tag.TagValue));
                if (tag.TagValue == 1)
                {
                    var tokens = field.ReadSequence();
                    if (!tokens.HasData) return false;
                    var item = tokens.ReadSequence();
                    var value = item.ReadSequence(Tag(0));
                    token = value.ReadOctetString();
                    value.ThrowIfNotEmpty();
                    item.ThrowIfNotEmpty();
                    // 一个认证轮次只协商一个机制，不接受多个歧义 token。
                    tokens.ThrowIfNotEmpty();
                }
                else if (tag.TagValue == 4)
                {
                    field.ReadInteger();
                }
                else
                {
                    field.ReadOctetString();
                }
                field.ThrowIfNotEmpty();
            }
            request = new(Math.Min(version, 6), token);
            return true;
        }
        catch (AsnContentException) { return false; }
    }

    public static bool TryExtractNtlmToken(ReadOnlySpan<byte> tsRequest, out byte[] token)
    {
        token = [];
        return TryReadRequest(tsRequest.ToArray(), out var request) && request.NegoToken is not null &&
            TryExtractNtlmMechanism(request.NegoToken, out token);
    }

    internal static bool TryExtractNtlmMechanism(ReadOnlyMemory<byte> data, out byte[] token)
        => TryFindNtlm(data, out token, 0);

    private static bool TryFindNtlm(ReadOnlyMemory<byte> data, out byte[] token, int depth)
    {
        token = [];
        if (depth > 12) return false;
        if (data.Span.StartsWith("NTLMSSP\0"u8)) { token = data.ToArray(); return true; }
        try
        {
            var reader = new AsnReader(data, AsnEncodingRules.DER);
            while (reader.HasData)
            {
                var tag = reader.PeekTag();
                if (tag.HasSameClassAndValue(Asn1Tag.PrimitiveOctetString))
                {
                    if (TryFindNtlm(reader.ReadOctetString(), out token, depth + 1)) return true;
                }
                else if (tag.IsConstructed)
                {
                    var child = reader.ReadSequence(tag);
                    while (child.HasData)
                    {
                        if (TryFindNtlm(child.ReadEncodedValue(), out token, depth + 1)) return true;
                    }
                }
                else reader.ReadEncodedValue();
            }
        }
        catch (AsnContentException) { return false; }
        return false;
    }

    public static bool TryParseNtlm(ReadOnlySpan<byte> token, out NtlmProtocol.NtlmMessage message)
        => NtlmProtocol.TryParse(token, out message);

    public static byte[] BuildNtlmChallenge(string hostName, uint clientFlags)
        => NtlmProtocol.BuildChallenge(hostName, clientFlags);

    public static byte[] BuildSpnegoChallenge(byte[] ntlmChallenge, int version = 6)
        => BuildTokenRequest(ntlmChallenge, version);

    internal static byte[] BuildChallenge(byte[] ntlmChallenge, int version, bool useSpnego)
        => BuildTokenRequest(ntlmChallenge, version, useSpnego);

    internal static byte[] BuildSpnegoAuthenticationRequest(byte[] ntlmResponse)
        => BuildTokenRequest(ntlmResponse, 6);

    private static byte[] BuildTokenRequest(byte[] token, int version, bool useSpnego = true)
    {
        // MS-CSSP 2.2.1 允许直接 NTLM 或 SPNEGO。保持客户端选择的封装，
        // 否则原生 NTLM 客户端会把额外的 NegTokenResp 当成无效 Type2，根本不会提交账号。
        if (useSpnego)
        {
            var spnego = new AsnWriter(AsnEncodingRules.DER);
            using (spnego.PushSequence(Tag(1)))
            using (spnego.PushSequence())
            {
                using (spnego.PushSequence(Tag(0))) spnego.WriteEnumeratedValue(NegotiationState.AcceptIncomplete);
                using (spnego.PushSequence(Tag(1))) spnego.WriteObjectIdentifier(NtlmOid);
                using (spnego.PushSequence(Tag(2))) spnego.WriteOctetString(token);
            }
            token = spnego.Encode();
        }
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            using (writer.PushSequence(Tag(0))) writer.WriteInteger(version);
            using (writer.PushSequence(Tag(1)))
            using (writer.PushSequence())
            using (writer.PushSequence())
            using (writer.PushSequence(Tag(0))) writer.WriteOctetString(token);
        }
        return writer.Encode();
    }

    public static byte[] BuildAuthenticationFailure(int version = 6)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            using (writer.PushSequence(Tag(0))) writer.WriteInteger(version);
            if (version is 2 or 5)
            {
                // MS-CSSP 2.2.1 的 errorCode 仅适用于 v3/v4/v6；v2/v5 用 SPNEGO reject。
                var reject = new AsnWriter(AsnEncodingRules.DER);
                using (reject.PushSequence(Tag(1)))
                using (reject.PushSequence())
                using (reject.PushSequence(Tag(0))) reject.WriteEnumeratedValue(NegotiationState.Reject);
                using (writer.PushSequence(Tag(1)))
                using (writer.PushSequence())
                using (writer.PushSequence())
                using (writer.PushSequence(Tag(0))) writer.WriteOctetString(reject.Encode());
            }
            else
            {
                // NTSTATUS 是 32 位有符号值；与 Windows/FreeRDP 一致使用四字节补码，
                // 不能编码成带额外前导零的五字节正整数。
                using (writer.PushSequence(Tag(4))) writer.WriteInteger(unchecked((int)0xC000006D));
            }
        }
        return writer.Encode();
    }

    private static Asn1Tag Tag(int value) => new(TagClass.ContextSpecific, value, true);
    private enum NegotiationState { AcceptIncomplete = 1, Reject = 2 }
}
