using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Honeypot.Protocol.Abstractions.Models;

namespace Honeypot.Protocols.Common;

/// <summary>仿真 TLS 只使用进程内生成的证书，人格主机名由服务配置提供。</summary>
public static class ProtocolTls
{
    private const int MaximumCachedCertificates = 256;
    private static readonly object Gate = new();
    private static readonly Dictionary<string, CachedCertificate> Cache = new(StringComparer.OrdinalIgnoreCase);

    public static X509Certificate2 GetServerCertificate(ServiceProfile profile)
    {
        var name = ProtocolFingerprint.HostName(profile);
        lock (Gate)
        {
            var now = DateTimeOffset.UtcNow;
            var lastUsed = TimeProvider.System.GetTimestamp();
            if (Cache.TryGetValue(name, out var cached) && now < cached.RefreshAtUtc)
            {
                cached.LastUsed = lastUsed;
                // 会话独立持有证书句柄，轮换或驱逐缓存时不影响现存握手和连接。
                return new X509Certificate2(cached.Certificate);
            }

            var certificate = CreateServerCertificate(name, now);
            if (cached is not null)
            {
                cached.Certificate.Dispose();
            }
            else if (Cache.Count >= MaximumCachedCertificates)
            {
                var oldest = Cache.MinBy(item => item.Value.LastUsed);
                Cache.Remove(oldest.Key);
                oldest.Value.Certificate.Dispose();
            }
            Cache[name] = new CachedCertificate(certificate, now.AddDays(6), lastUsed);
            return new X509Certificate2(certificate);
        }
    }

    private static X509Certificate2 CreateServerCertificate(string name, DateTimeOffset now)
    {
        // 主机名来自人格配置；使用结构化 DN/SAN，避免配置被解释成任意证书主题。
        var subject = new X500DistinguishedNameBuilder();
        subject.AddCommonName(name);
        var names = new SubjectAlternativeNameBuilder();
        if (IPAddress.TryParse(name, out var address)) names.AddIpAddress(address);
        else names.AddDnsName(name);
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(subject.Build(), rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new("1.3.6.1.5.5.7.3.1") }, false));
        request.CertificateExtensions.Add(names.Build());
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        return request.CreateSelfSigned(now.AddMinutes(-5), now.AddDays(7));
    }

    private sealed class CachedCertificate(X509Certificate2 certificate, DateTimeOffset refreshAtUtc, long lastUsed)
    {
        public X509Certificate2 Certificate { get; } = certificate;
        public DateTimeOffset RefreshAtUtc { get; } = refreshAtUtc;
        public long LastUsed { get; set; } = lastUsed;
    }
}
