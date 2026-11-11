using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Honeypot.Api.Common;
using Honeypot.Api.Models;
using Honeypot.Shared.Models;

namespace Honeypot.Api.Service.impl;

/// <summary>SMTP 授权码只存 AES-GCM 密文；密钥单独持久化，丢失时拒绝解密和覆盖。</summary>
public sealed class FileNotificationSettingsStore : INotificationSettingsStore
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web) { WriteIndented = true };
    private static readonly byte[] AssociatedData = Encoding.UTF8.GetBytes("Honeypot.Notification.Smtp.v1");
    private readonly string _directory;
    private readonly string _path;
    private readonly string _keyDirectory;
    private readonly string _keyPath;
    private readonly TimeProvider _time;
    private readonly SemaphoreSlim _gate = new(1, 1);

    public FileNotificationSettingsStore(IConfiguration configuration, IHostEnvironment environment, TimeProvider time)
    {
        var dataDirectory = configuration["Honeypot:DataDirectory"];
        if (string.IsNullOrWhiteSpace(dataDirectory)) dataDirectory = Path.Combine(environment.ContentRootPath, "data");
        _directory = Path.Combine(dataDirectory, "notifications");
        _path = Path.Combine(_directory, "settings.json");
        var configuredKeyDirectory = configuration["Honeypot:NotificationKeyDirectory"];
        _keyDirectory = string.IsNullOrWhiteSpace(configuredKeyDirectory) ? Path.Combine(_directory, "keys") : configuredKeyDirectory;
        _keyPath = Path.Combine(_keyDirectory, "smtp.key");
        _time = time;
    }

    public async Task<NotificationSettings> GetAsync(CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken);
        try { return Readable(await LoadAsync(cancellationToken)); }
        finally { _gate.Release(); }
    }

    public async Task<NotificationSettings> SaveAsync(UpdateNotificationSettingsRequest request, CancellationToken cancellationToken = default)
    {
        if (request is null) throw new NotificationException("VALIDATION_ERROR", "通知配置不能为空。");
        await _gate.WaitAsync(cancellationToken);
        try
        {
            var previous = await LoadAsync(cancellationToken);
            var hasNewCredential = !string.IsNullOrEmpty(request.AuthorizationCode);
            if (request.AuthorizationCode?.Length > 4096 || request.AuthorizationCode?.Any(char.IsControl) == true ||
                (hasNewCredential && string.IsNullOrWhiteSpace(request.AuthorizationCode)))
                throw new NotificationException("VALIDATION_ERROR", "授权码长度或格式无效。");
            var normalized = NotificationSettingsValidation.Normalize(request.Settings, hasNewCredential || previous.CredentialCiphertext is not null);
            var ciphertext = previous.CredentialCiphertext;
            if (hasNewCredential)
            {
                var key = await ReadKeyAsync(ciphertext is null, cancellationToken);
                try { ciphertext = Encrypt(request.AuthorizationCode!, key); }
                finally { CryptographicOperations.ZeroMemory(key); }
            }
            var now = _time.GetUtcNow();
            var activated = new Dictionary<string, DateTimeOffset>(previous.ActivatedAtUtc, StringComparer.Ordinal);
            normalized = normalized with
            {
                Schedules = normalized.Schedules.Select(schedule =>
                {
                    var old = previous.Settings.Schedules.FirstOrDefault(item => item.Kind == schedule.Kind);
                    if (schedule.Enabled && (!previous.Settings.Enabled || old?.Enabled != true || old.SendTime != schedule.SendTime || !activated.ContainsKey(schedule.Kind)))
                        activated[schedule.Kind] = now;
                    return schedule with { LastRunAtUtc = old?.LastRunAtUtc, LastRunStatus = old?.LastRunStatus };
                }).ToArray()
            };
            var saved = new StoredSettings { Settings = normalized, CredentialCiphertext = ciphertext, ActivatedAtUtc = activated };
            await WriteAsync(saved, cancellationToken);
            return Readable(saved);
        }
        finally { _gate.Release(); }
    }

    public async Task<NotificationTransportSettings> GetTransportAsync(CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            var saved = await LoadAsync(cancellationToken);
            var settings = saved.Settings;
            if (saved.CredentialCiphertext is null) throw new NotificationException("SMTP_CREDENTIAL_MISSING", "尚未配置邮件授权码。");
            var key = await ReadKeyAsync(false, cancellationToken);
            string credential;
            try { credential = Decrypt(saved.CredentialCiphertext, key); }
            catch (Exception error) when (error is CryptographicException or FormatException)
            { throw new NotificationException("SMTP_CREDENTIAL_UNAVAILABLE", "邮件授权码无法解密，请检查保护密钥。"); }
            finally { CryptographicOperations.ZeroMemory(key); }
            return new(settings.Enabled, settings.Host, settings.Port, settings.SecurityMode, settings.FromEmail,
                settings.FromName, settings.Username, credential, settings.TimeoutSeconds);
        }
        finally { _gate.Release(); }
    }

    public async Task<IReadOnlyList<NotificationScheduleState>> GetScheduleStatesAsync(CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            var saved = await LoadAsync(cancellationToken);
            if (!saved.Settings.Enabled) return [];
            return saved.Settings.Schedules.Where(schedule => schedule.Enabled && saved.ActivatedAtUtc.ContainsKey(schedule.Kind))
                .Select(schedule => new NotificationScheduleState(schedule, saved.ActivatedAtUtc[schedule.Kind])).ToArray();
        }
        finally { _gate.Release(); }
    }

    public async Task RecordScheduleRunAsync(string kind, DateTimeOffset? scheduledAtUtc, string status, CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            var saved = await LoadAsync(cancellationToken);
            saved = saved with { Settings = saved.Settings with { Schedules = saved.Settings.Schedules.Select(schedule =>
                schedule.Kind == kind ? schedule with { LastRunAtUtc = scheduledAtUtc ?? schedule.LastRunAtUtc, LastRunStatus = status } : schedule).ToArray() } };
            await WriteAsync(saved, cancellationToken);
        }
        finally { _gate.Release(); }
    }

    private NotificationSettings Readable(StoredSettings saved) => saved.Settings with
    {
        HasCredential = saved.CredentialCiphertext is not null,
        Schedules = saved.Settings.Schedules.Select(schedule => schedule with
        {
            NextRunAtUtc = saved.Settings.Enabled && schedule.Enabled ? NotificationScheduleCalculator.Next(schedule.Kind, schedule.SendTime, _time.GetUtcNow()) : null
        }).ToArray()
    };

    private async Task<StoredSettings> LoadAsync(CancellationToken cancellationToken)
    {
        if (!File.Exists(_path)) return new();
        try
        {
            if (new FileInfo(_path).Length > 65536) throw new JsonException();
            var saved = JsonSerializer.Deserialize<StoredSettings>(await File.ReadAllTextAsync(_path, cancellationToken), JsonOptions) ?? throw new JsonException();
            if (saved.ActivatedAtUtc is null) throw new JsonException();
            // 只校验，不抹掉服务端保存的调度状态。
            _ = NotificationSettingsValidation.Normalize(saved.Settings, saved.CredentialCiphertext is not null);
            return saved;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or JsonException or NotificationException)
        { throw new NotificationException("NOTIFICATION_CONFIGURATION_UNAVAILABLE", "通知配置无法读取，请检查配置文件，系统不会自动覆盖现有配置。"); }
    }

    private async Task WriteAsync(StoredSettings settings, CancellationToken cancellationToken)
    {
        try
        {
            CreatePrivateDirectory(_directory);
            var temporaryPath = _path + ".tmp";
            await WritePrivateFileAsync(temporaryPath, Encoding.UTF8.GetBytes(JsonSerializer.Serialize(settings, JsonOptions)), FileMode.Create, cancellationToken);
            File.Move(temporaryPath, _path, true);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        { throw new NotificationException("NOTIFICATION_CONFIGURATION_WRITE_FAILED", "通知配置保存失败，请检查数据目录权限。"); }
    }

    private async Task<byte[]> ReadKeyAsync(bool mayCreate, CancellationToken cancellationToken)
    {
        try
        {
            if (!File.Exists(_keyPath))
            {
                if (!mayCreate) throw new NotificationException("SMTP_PROTECTION_KEY_MISSING", "邮件保护密钥缺失，禁止自动重新生成以免覆盖已有授权码。");
                CreatePrivateDirectory(_keyDirectory);
                var generated = RandomNumberGenerator.GetBytes(32);
                try { await WritePrivateFileAsync(_keyPath, generated, FileMode.CreateNew, cancellationToken); }
                finally { CryptographicOperations.ZeroMemory(generated); }
            }
            var key = await File.ReadAllBytesAsync(_keyPath, cancellationToken);
            if (key.Length != 32)
            {
                CryptographicOperations.ZeroMemory(key);
                throw new NotificationException("SMTP_PROTECTION_KEY_INVALID", "邮件保护密钥无效。");
            }
            return key;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        { throw new NotificationException("SMTP_PROTECTION_KEY_UNAVAILABLE", "邮件保护密钥无法访问。"); }
    }

    private static string Encrypt(string value, byte[] key)
    {
        var plaintext = Encoding.UTF8.GetBytes(value);
        var protectedBytes = new byte[12 + 16 + plaintext.Length];
        RandomNumberGenerator.Fill(protectedBytes.AsSpan(0, 12));
        try
        {
            using var aes = new AesGcm(key, 16);
            aes.Encrypt(protectedBytes.AsSpan(0, 12), plaintext, protectedBytes.AsSpan(28), protectedBytes.AsSpan(12, 16), AssociatedData);
            return Convert.ToBase64String(protectedBytes);
        }
        finally { CryptographicOperations.ZeroMemory(plaintext); }
    }

    private static string Decrypt(string value, byte[] key)
    {
        var protectedBytes = Convert.FromBase64String(value);
        if (protectedBytes.Length < 28) throw new CryptographicException();
        var plaintext = new byte[protectedBytes.Length - 28];
        try
        {
            using var aes = new AesGcm(key, 16);
            aes.Decrypt(protectedBytes.AsSpan(0, 12), protectedBytes.AsSpan(28), protectedBytes.AsSpan(12, 16), plaintext, AssociatedData);
            return Encoding.UTF8.GetString(plaintext);
        }
        finally { CryptographicOperations.ZeroMemory(plaintext); }
    }

    private static void CreatePrivateDirectory(string path)
    {
        if (OperatingSystem.IsWindows()) Directory.CreateDirectory(path);
        else
        {
            Directory.CreateDirectory(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
    }

    private static async Task WritePrivateFileAsync(string path, byte[] bytes, FileMode mode, CancellationToken cancellationToken)
    {
        var options = new FileStreamOptions { Mode = mode, Access = FileAccess.Write, Share = FileShare.None, Options = FileOptions.Asynchronous };
        if (!OperatingSystem.IsWindows()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        await using var stream = new FileStream(path, options);
        if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        await stream.WriteAsync(bytes, cancellationToken);
        await stream.FlushAsync(cancellationToken);
    }

    private sealed record StoredSettings
    {
        public NotificationSettings Settings { get; init; } = new();
        public string? CredentialCiphertext { get; init; }
        public Dictionary<string, DateTimeOffset> ActivatedAtUtc { get; init; } = new(StringComparer.Ordinal);
    }
}
