using System.Formats.Asn1;
using Honeypot.Protocols.Common;

namespace Honeypot.Protocols.Smb.Common;

/// <summary>只解析 RFC 4178 定义的安全令牌字段，不通过任意子串猜测 NTLM 凭据。</summary>
internal static class SmbSpnego
{
    private const string SpnegoOid = "1.3.6.1.5.5.2";
    private const string NtlmOid = "1.3.6.1.4.1.311.2.2.10";
    private static Asn1Tag Tag(int value) => new(TagClass.ContextSpecific, value, true);

    public static byte[] NegotiateToken()
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence(new Asn1Tag(TagClass.Application, 0, true)))
        {
            writer.WriteObjectIdentifier(SpnegoOid);
            using (writer.PushSequence(Tag(0)))
            using (writer.PushSequence())
            using (writer.PushSequence(Tag(0)))
            using (writer.PushSequence()) writer.WriteObjectIdentifier(NtlmOid);
        }
        return writer.Encode();
    }

    public static bool TryNtlm(ReadOnlyMemory<byte> data, out NtlmProtocol.NtlmMessage message, out bool wrapped)
    {
        wrapped = false;
        if (NtlmProtocol.TryParse(data.Span, out message)) return true;
        message = default;
        try
        {
            var reader = new AsnReader(data, AsnEncodingRules.DER);
            if (reader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.Application, 0, true)))
            {
                var envelope = reader.ReadSequence(new Asn1Tag(TagClass.Application, 0, true));
                reader.ThrowIfNotEmpty();
                if (envelope.ReadObjectIdentifier() != SpnegoOid) return false;
                reader = envelope;
            }
            var tag = reader.PeekTag();
            if (!tag.HasSameClassAndValue(Tag(0)) && !tag.HasSameClassAndValue(Tag(1))) return false;
            var choice = reader.ReadSequence(tag); reader.ThrowIfNotEmpty();
            var fields = choice.ReadSequence(); choice.ThrowIfNotEmpty();
            byte[]? token = null;
            var seen = new HashSet<int>();
            while (fields.HasData)
            {
                var fieldTag = fields.PeekTag();
                if (fieldTag.TagClass != TagClass.ContextSpecific || fieldTag.TagValue > 3 || !seen.Add(fieldTag.TagValue)) return false;
                if (fieldTag.TagValue == 2)
                {
                    var field = fields.ReadSequence(Tag(2));
                    token = field.ReadOctetString(); field.ThrowIfNotEmpty();
                }
                else fields.ReadEncodedValue();
            }
            if (token is null || !NtlmProtocol.TryParse(token, out message)) return false;
            wrapped = true;
            return true;
        }
        catch (AsnContentException) { return false; }
    }

    public static bool IsOtherAuthenticationToken(ReadOnlyMemory<byte> data)
    {
        // 对实际送达的 Kerberos 初始令牌只做有界存证，不调用宿主 GSS/KDC。
        // 不接受任意字节串作为一次登录，以免畸形请求被计入密码尝试。
        try
        {
            var reader = new AsnReader(data, AsnEncodingRules.DER);
            var envelope = reader.ReadSequence(new Asn1Tag(TagClass.Application, 0, true));
            reader.ThrowIfNotEmpty();
            var oid = envelope.ReadObjectIdentifier();
            if (oid is "1.2.840.113554.1.2.2" or "1.2.840.48018.1.2.2") return envelope.HasData;
            if (oid != SpnegoOid) return false;
            var choice = envelope.ReadSequence(Tag(0)); envelope.ThrowIfNotEmpty();
            var fields = choice.ReadSequence(); choice.ThrowIfNotEmpty();
            var mechanisms = fields.ReadSequence(Tag(0));
            var list = mechanisms.ReadSequence(); mechanisms.ThrowIfNotEmpty();
            var kerberos = false;
            for (var count = 0; list.HasData && count < 16; count++)
                kerberos |= list.ReadObjectIdentifier() is "1.2.840.113554.1.2.2" or "1.2.840.48018.1.2.2";
            list.ThrowIfNotEmpty();
            if (fields.HasData && fields.PeekTag().HasSameClassAndValue(Tag(1))) fields.ReadEncodedValue();
            var tokenField = fields.ReadSequence(Tag(2)); var token = tokenField.ReadOctetString(); tokenField.ThrowIfNotEmpty();
            if (fields.HasData && fields.PeekTag().HasSameClassAndValue(Tag(3))) fields.ReadEncodedValue();
            fields.ThrowIfNotEmpty();
            return kerberos && token.Length > 0;
        }
        catch (AsnContentException) { return false; }
    }

    public static byte[] Challenge(byte[] ntlm, bool wrapped)
    {
        if (!wrapped) return ntlm;
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence(Tag(1)))
        using (writer.PushSequence())
        {
            using (writer.PushSequence(Tag(0))) writer.WriteEnumeratedValue(NegotiationState.AcceptIncomplete);
            using (writer.PushSequence(Tag(1))) writer.WriteObjectIdentifier(NtlmOid);
            using (writer.PushSequence(Tag(2))) writer.WriteOctetString(ntlm);
        }
        return writer.Encode();
    }

    private enum NegotiationState { AcceptIncomplete = 1 }
}
