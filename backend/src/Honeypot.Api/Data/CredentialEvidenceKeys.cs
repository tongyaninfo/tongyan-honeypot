using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using Honeypot.Api.Options;
using Microsoft.Extensions.Options;

namespace Honeypot.Api.Data;

/// <summary>独立保管证据 AES 和密码簿 HMAC 密钥。已有密文时禁止生成替代密钥。</summary>
public sealed class CredentialEvidenceKeys(IConfiguration configuration, IHostEnvironment environment,
    IOptions<CredentialEvidenceOptions> options)
{
    private const UnixFileMode PrivateFile = UnixFileMode.UserRead | UnixFileMode.UserWrite;
    private const UnixFileMode PrivateDirectory = PrivateFile | UnixFileMode.UserExecute;
    private readonly object _gate = new();

    internal KeyMaterial Read(bool mayInitialize)
    {
        var directory = string.IsNullOrWhiteSpace(options.Value.KeyDirectory)
            ? Path.Combine(HoneypotDbOptions.ResolveDataDirectory(configuration, environment), "credential-evidence-keys")
            : options.Value.KeyDirectory;
        var path = Path.Combine(directory, "evidence-v1.key");
        lock (_gate)
        {
            if (Directory.Exists(directory)) ValidateDirectory(directory);
            if (!File.Exists(path) && mayInitialize) Create(path, directory);

            var info = new FileInfo(path);
            if (!info.Exists || info.LinkTarget is not null)
                throw new CryptographicException("CREDENTIAL_EVIDENCE_KEY_UNAVAILABLE");
            if (!OperatingSystem.IsWindows() && (File.GetUnixFileMode(path) & ~PrivateFile) != 0)
                throw new CryptographicException("CREDENTIAL_EVIDENCE_KEY_PERMISSIONS_INVALID");

            // 只读取固定长度，损坏的密钥文件不能消耗无界内存，也不会被自动替换。
            using var file = info.OpenRead();
            if (file.Length != KeyMaterial.KeyLength * 2)
                throw new CryptographicException("CREDENTIAL_EVIDENCE_KEY_INVALID");
            var bytes = new byte[KeyMaterial.KeyLength * 2];
            try
            {
                file.ReadExactly(bytes);
                return new KeyMaterial(bytes);
            }
            finally { CryptographicOperations.ZeroMemory(bytes); }
        }
    }

    private static void Create(string path, string directory)
    {
        var generated = RandomNumberGenerator.GetBytes(KeyMaterial.KeyLength * 2);
        try
        {
            if (OperatingSystem.IsWindows()) Directory.CreateDirectory(directory);
            else Directory.CreateDirectory(directory, PrivateDirectory);
            ValidateDirectory(directory);
            // 直接用受限权限创建文件，CreateNew 保证现存密钥永远不会被覆盖。
            using var file = OpenNewPrivateFile(path);
            file.Write(generated);
            file.Flush(flushToDisk: true);
        }
        finally { CryptographicOperations.ZeroMemory(generated); }
    }

    private static void ValidateDirectory(string directory)
    {
        if (new DirectoryInfo(directory).LinkTarget is not null ||
            (!OperatingSystem.IsWindows() &&
                (File.GetUnixFileMode(directory) & (UnixFileMode.GroupWrite | UnixFileMode.OtherWrite)) != 0))
            throw new CryptographicException("CREDENTIAL_EVIDENCE_KEY_DIRECTORY_UNSAFE");
    }

    private static FileStream OpenNewPrivateFile(string path)
    {
        if (!OperatingSystem.IsWindows())
            return new FileStream(path, new FileStreamOptions
            {
                Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None, UnixCreateMode = PrivateFile,
            });

        using var identity = WindowsIdentity.GetCurrent();
        var owner = identity.User ?? throw new CryptographicException("CREDENTIAL_EVIDENCE_KEY_OWNER_UNAVAILABLE");
        var security = new FileSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new FileSystemAccessRule(owner, FileSystemRights.FullControl, AccessControlType.Allow));
        return new FileInfo(path).Create(FileMode.CreateNew, FileSystemRights.Write, FileShare.None, 4096, FileOptions.None, security);
    }

    internal sealed class KeyMaterial(byte[] bytes) : IDisposable
    {
        internal const int KeyLength = 32;
        internal byte[] EncryptionKey { get; } = bytes[..KeyLength];
        internal byte[] FingerprintKey { get; } = bytes[KeyLength..];
        internal string Id { get; } = Convert.ToHexString(SHA256.HashData(bytes));

        public void Dispose()
        {
            CryptographicOperations.ZeroMemory(EncryptionKey);
            CryptographicOperations.ZeroMemory(FingerprintKey);
        }
    }
}
