using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Hosting;

namespace Honeypot.Api.Common;

internal static class ManagementHttps
{
    private const string DefaultUrl = "https://localhost:5080";

    public static void UseManagementHttps(this WebApplicationBuilder builder)
    {
        var kestrel = builder.Configuration.GetSection("Kestrel");
        var serverUrls = builder.Configuration[WebHostDefaults.ServerUrlsKey];
        if (string.IsNullOrWhiteSpace(serverUrls))
        {
            serverUrls = DefaultUrl;
        }

        var configuredUrls = serverUrls.Split(';', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        var endpointUrls = kestrel.GetSection("Endpoints").GetChildren().Select(endpoint => endpoint["Url"]).ToArray();
        if (configuredUrls.Length == 0 || configuredUrls.Concat(endpointUrls).Any(url =>
            url is null || !url.StartsWith("https://", StringComparison.OrdinalIgnoreCase)))
        {
            throw new InvalidOperationException("管理端仅支持 HTTPS。请将 Urls 和 Kestrel:Endpoints 中的监听地址设为 https://。");
        }

        builder.WebHost.UseUrls(configuredUrls);
        builder.Services.AddSingleton<ManagementCertificate>();
        builder.WebHost.ConfigureKestrel(options =>
        {
            // 启动时统一验证明文端点。修改绑定地址或证书配置后重启应用。
            options.Configure(kestrel, reloadOnChange: false);
            options.ConfigureHttpsDefaults(https =>
            {
                var configuredCertificate = kestrel.GetSection("Certificates:Default");
                if (string.IsNullOrWhiteSpace(configuredCertificate["Path"]) &&
                    string.IsNullOrWhiteSpace(configuredCertificate["Subject"]))
                {
                    https.ServerCertificate = options.ApplicationServices.GetRequiredService<ManagementCertificate>().Certificate;
                }
            });
        });
    }

    public static async Task<int> ProbeLoopbackAsync()
    {
        // 容器健康检查只访问本机固定端口。探测请求不带凭据，也不跟随重定向。
        using var handler = new HttpClientHandler
        {
            AllowAutoRedirect = false,
            UseProxy = false,
            ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator,
        };
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(3) };
        try
        {
            using var response = await client.GetAsync("https://127.0.0.1:5080/health", HttpCompletionOption.ResponseHeadersRead);
            return response.StatusCode == HttpStatusCode.OK ? 0 : 1;
        }
        catch (Exception error) when (error is HttpRequestException or OperationCanceledException)
        {
            return 1;
        }
    }

    private sealed class ManagementCertificate : IDisposable
    {
        public ManagementCertificate(IConfiguration configuration, ILogger<ManagementCertificate> logger)
        {
            // 管理证书由独立密钥在当前进程内生成，只有 Kestrel 管理端使用。
            using var key = RSA.Create(2048);
            var request = new CertificateRequest("CN=Honeypot Management", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new("1.3.6.1.5.5.7.3.1") }, false));

            var names = new SubjectAlternativeNameBuilder();
            var configuredNames = configuration.GetSection("Honeypot:ManagementHttps:CertificateNames").Get<string[]>() ?? [];
            foreach (var name in new[] { "localhost", "127.0.0.1", "::1" }.Concat(configuredNames).Distinct(StringComparer.OrdinalIgnoreCase))
            {
                if (IPAddress.TryParse(name, out var address)) names.AddIpAddress(address);
                else names.AddDnsName(name);
            }
            request.CertificateExtensions.Add(names.Build());
            var now = DateTimeOffset.UtcNow;
            Certificate = request.CreateSelfSigned(now.AddMinutes(-5), now.AddYears(1));
            logger.LogInformation("Management HTTPS uses a self-signed certificate. SHA-256 fingerprint: {Fingerprint}",
                Certificate.GetCertHashString(HashAlgorithmName.SHA256));
        }

        public X509Certificate2 Certificate { get; }

        public void Dispose() => Certificate.Dispose();
    }
}
