using System.Buffers.Binary;
using System.Formats.Asn1;
using Honeypot.Protocols.Common;

namespace Honeypot.Protocols.MsSql.Common;

/// <summary>接受原始 NTLM 或 SPNEGO 包装；不建立系统 SSPI 上下文或访问域控制器。</summary>
internal static class TdsSspi
{
    public static bool TryReadNtlm(ReadOnlyMemory<byte> data, out NtlmProtocol.NtlmMessage message, out bool wrapped)
    {
        wrapped = false;
        if (NtlmProtocol.TryParse(data.Span, out message)) return true;
        message = default;
        if (data.Length == 0 || data.Span[0] is not (0x60 or 0xA0 or 0xA1)) return false;
        try
        {
            var reader = new AsnReader(data, AsnEncodingRules.DER);
            var candidates = new List<byte[]>();
            var remaining = 256;
            Collect(reader, candidates, 0, ref remaining);
            if (candidates.Count != 1 || !NtlmProtocol.TryParse(candidates[0], out message)) return false;
            wrapped = true;
            return true;
        }
        catch (AsnContentException) { return false; }
    }

    private static void Collect(AsnReader reader, List<byte[]> candidates, int depth, ref int remaining)
    {
        if (depth > 12) throw new AsnContentException();
        while (reader.HasData)
        {
            if (--remaining < 0) throw new AsnContentException();
            var tag = reader.PeekTag();
            if (tag.HasSameClassAndValue(Asn1Tag.PrimitiveOctetString))
            {
                var value = reader.ReadOctetString();
                if (value.AsSpan().StartsWith("NTLMSSP\0"u8)) candidates.Add(value);
            }
            else if (tag.IsConstructed) Collect(reader.ReadSequence(tag), candidates, depth + 1, ref remaining);
            else reader.ReadEncodedValue();
        }
    }

    public static byte[] BuildChallenge(byte[] ntlm, bool wrapped)
    {
        byte[] token = ntlm;
        if (wrapped)
        {
            var writer = new AsnWriter(AsnEncodingRules.DER);
            var response = new Asn1Tag(TagClass.ContextSpecific, 1, true);
            var state = new Asn1Tag(TagClass.ContextSpecific, 0, true);
            var mechanism = new Asn1Tag(TagClass.ContextSpecific, 1, true);
            var responseToken = new Asn1Tag(TagClass.ContextSpecific, 2, true);
            using (writer.PushSequence(response))
            using (writer.PushSequence())
            {
                using (writer.PushSequence(state)) writer.WriteEnumeratedValue(NegotiationState.AcceptIncomplete);
                using (writer.PushSequence(mechanism)) writer.WriteObjectIdentifier("1.3.6.1.4.1.311.2.2.10");
                using (writer.PushSequence(responseToken)) writer.WriteOctetString(ntlm);
            }
            token = writer.Encode();
        }
        var result = new byte[token.Length + 3];
        result[0] = 0xED; // SSPI token，长度为小端字节数。
        BinaryPrimitives.WriteUInt16LittleEndian(result.AsSpan(1), checked((ushort)token.Length));
        token.CopyTo(result, 3);
        return result;
    }

    private enum NegotiationState { AcceptIncomplete = 1 }
}
