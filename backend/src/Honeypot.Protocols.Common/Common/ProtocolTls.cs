using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Honeypot.Protocols.Common;

/// <summary>隔离蜜罐的进程内 TLS 证书，不读取、写入或修改宿主的证书和密钥文件。</summary>
public static class ProtocolTls
{
    public static X509Certificate2 CreateServerCertificate(string hostName)
    {
        // 主机名来自人格配置；使用结构化 DN/SAN，避免配置被解释成任意证书主题。
        var name = string.IsNullOrWhiteSpace(hostName) ? "localhost" : hostName;
        var subject = new X500DistinguishedNameBuilder();
        subject.AddCommonName(name);
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(subject.Build(), rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new("1.3.6.1.5.5.7.3.1") }, false));
        var names = new SubjectAlternativeNameBuilder();
        if (IPAddress.TryParse(name, out var address)) names.AddIpAddress(address);
        else names.AddDnsName(name);
        request.CertificateExtensions.Add(names.Build());
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(7));
    }
}
