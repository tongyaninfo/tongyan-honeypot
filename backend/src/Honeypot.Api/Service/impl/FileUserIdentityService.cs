using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.RateLimiting;
using Honeypot.Api.Models;
using Honeypot.Api.Options;
using Honeypot.Api.Service;
using Honeypot.Shared.Models;

namespace Honeypot.Api.Service.impl;

/// <summary>文件持久化用户服务。首个管理员必须通过初始化接口创建。</summary>
public sealed class FileUserIdentityService : IUserIdentityService, IDisposable
{
    private const int SaltSize = 16;
    private const int HashSize = 32;
    private const int Iterations = 600_000;
    private static readonly Regex UsernamePattern = new("^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$", RegexOptions.Compiled);
    private readonly object _sync = new();
    private readonly string _usersFilePath;
    private readonly string _loginLockoutPath;
    private readonly TimeSpan _sessionLifetime;
    private readonly LoginLockoutOptions _lockout;
    private readonly TimeProvider _clock;
    private readonly ISyslogPublisher? _logs;
    // 串行校验密码，使成功、失败与锁定有确定顺序，同时限制等待哈希校验的请求数。
    private readonly ConcurrencyLimiter _loginGate = new(new ConcurrencyLimiterOptions
    {
        PermitLimit = 1, QueueLimit = 16, QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
    });
    private int _failedAttempts;
    private DateTimeOffset? _lockedUntilUtc;
    private readonly ConcurrentDictionary<string, (AuthenticatedUser User, DateTimeOffset ExpiresAtUtc)> _sessions = new(StringComparer.Ordinal);
    private readonly JsonSerializerOptions _jsonOptions = new(JsonSerializerDefaults.Web) { WriteIndented = true };
    private List<UserAccount> _users;

    public FileUserIdentityService(IConfiguration configuration, IWebHostEnvironment environment, ISyslogPublisher? logs = null,
        TimeProvider? clock = null)
    {
        var dataDirectory = configuration["Honeypot:DataDirectory"];
        if (string.IsNullOrWhiteSpace(dataDirectory))
        {
            dataDirectory = Path.Combine(environment.ContentRootPath, "data");
        }

        Directory.CreateDirectory(dataDirectory);
        _usersFilePath = Path.Combine(dataDirectory, "users.json");
        _loginLockoutPath = Path.Combine(dataDirectory, "login-lockout.json");
        _sessionLifetime = TimeSpan.FromHours(configuration.GetValue("Honeypot:SessionLifetimeHours", 8));
        _lockout = LoginLockoutOptions.Read(configuration);
        _clock = clock ?? TimeProvider.System;
        _logs = logs;
        try
        {
            _users = LoadUsers();
            if (File.Exists(_loginLockoutPath))
                _lockedUntilUtc = JsonSerializer.Deserialize<DateTimeOffset>(File.ReadAllText(_loginLockoutPath));
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or InvalidOperationException or JsonException)
        {
            logs?.Publish("honeypot-identity", "IDENTITY_STORE_UNAVAILABLE", SyslogSeverity.Critical,
                new Dictionary<string, object?> { ["exceptionType"] = error.GetType().Name });
            throw;
        }
    }

    public bool IsInitialized
    {
        get
        {
            lock (_sync)
            {
                return _users.Count > 0;
            }
        }
    }

    public async Task<(bool Succeeded, string Code, string Message)> InitializeFirstAdminAsync(string username, string password, CancellationToken cancellationToken = default)
    {
        username = username.Trim();
        var validation = ValidateCredentials(username, password);
        if (validation is not null)
        {
            return (false, validation.Value.Code, validation.Value.Message);
        }

        lock (_sync)
        {
            if (_users.Count > 0)
            {
                return (false, "ALREADY_INITIALIZED", "系统已经完成初始化。");
            }

            var salt = RandomNumberGenerator.GetBytes(SaltSize);
            _users.Add(new UserAccount($"user-{Guid.NewGuid():N}", username, Convert.ToBase64String(HashPassword(password, salt)), Convert.ToBase64String(salt), new[] { "Administrator" }, DateTimeOffset.UtcNow, false));
            SaveUsers(cancellationToken);
        }

        await Task.CompletedTask;
        return (true, "OK", "初始化管理员创建成功。");
    }

    public async Task<LoginAttemptResult> LoginAsync(string? username, string? password, CancellationToken cancellationToken = default)
    {
        using var lease = await _loginGate.AcquireAsync(cancellationToken: cancellationToken);
        if (!lease.IsAcquired) return new(Busy: true);

        if (_lockedUntilUtc is { } lockedUntil)
        {
            if (lockedUntil > _clock.GetUtcNow()) return new(LockedUntilUtc: lockedUntil);
            _lockedUntilUtc = null;
            _failedAttempts = 0;
        }

        var loginName = username?.Trim();
        UserAccount? account;
        lock (_sync)
        {
            // 管理员初始化之前没有可校验的账号，登录请求不应阻塞首次初始化。
            if (_users.Count == 0) return new();
            account = _users.FirstOrDefault(item => item.Username.Equals(loginName, StringComparison.OrdinalIgnoreCase));
        }

        if (account is null || account.Disabled || password is null || !VerifyPassword(password, account.PasswordHash, account.PasswordSalt))
        {
            if (++_failedAttempts < _lockout.MaxFailedAttempts) return new();

            var deadline = _clock.GetUtcNow().Add(_lockout.Duration);
            _lockedUntilUtc = deadline;
            // 仅持久化已生效的截止时间，部署重启不能提前解除锁定。文件不含凭据。
            try
            {
                var temporaryPath = _loginLockoutPath + ".tmp";
                File.WriteAllText(temporaryPath, JsonSerializer.Serialize(deadline));
                File.Move(temporaryPath, _loginLockoutPath, overwrite: true);
            }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException)
            {
                _logs?.Publish("honeypot-identity", "LOGIN_LOCKOUT_PERSISTENCE_FAILED", SyslogSeverity.Error,
                    new Dictionary<string, object?> { ["exceptionType"] = error.GetType().Name });
            }
            return new(LockedUntilUtc: deadline, LockoutStarted: true);
        }

        _failedAttempts = 0;
        var user = new AuthenticatedUser(account.UserId, account.Username, account.Roles);
        var expiresAt = _clock.GetUtcNow().Add(_sessionLifetime);
        var token = CreateToken();
        _sessions[token] = (user, expiresAt);
        return new(new LoginResult(token, expiresAt, user));
    }

    public bool TryAuthenticate(string accessToken, out AuthenticatedUser? user)
    {
        user = null;
        if (string.IsNullOrWhiteSpace(accessToken) || !_sessions.TryGetValue(accessToken, out var session))
        {
            return false;
        }

        if (session.ExpiresAtUtc <= _clock.GetUtcNow())
        {
            _sessions.TryRemove(accessToken, out _);
            return false;
        }

        user = session.User;
        return true;
    }

    public void Logout(string accessToken)
    {
        if (!string.IsNullOrWhiteSpace(accessToken))
        {
            _sessions.TryRemove(accessToken, out _);
        }
    }

    public IReadOnlyCollection<AuthenticatedUser> GetUsers()
    {
        lock (_sync)
        {
            return _users.Where(item => !item.Disabled)
                .Select(item => new AuthenticatedUser(item.UserId, item.Username, item.Roles))
                .ToArray();
        }
    }

    private List<UserAccount> LoadUsers()
    {
        if (!File.Exists(_usersFilePath))
        {
            return new List<UserAccount>();
        }

        try
        {
            var json = File.ReadAllText(_usersFilePath, Encoding.UTF8);
            return JsonSerializer.Deserialize<List<UserAccount>>(json, _jsonOptions) ?? new List<UserAccount>();
        }
        catch (JsonException)
        {
            throw new InvalidOperationException("USER_STORE_INVALID");
        }
    }

    private void SaveUsers(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var json = JsonSerializer.Serialize(_users, _jsonOptions);
        var temporaryPath = $"{_usersFilePath}.{Guid.NewGuid():N}.tmp";
        File.WriteAllText(temporaryPath, json, new UTF8Encoding(false));
        File.Move(temporaryPath, _usersFilePath, true);
    }

    private static (string Code, string Message)? ValidateCredentials(string username, string password)
    {
        if (!UsernamePattern.IsMatch(username))
        {
            return ("INVALID_USERNAME", "用户名需要为 3-64 位字母、数字、点、下划线或短横线。");
        }

        if (string.IsNullOrEmpty(password) || password.Length < 8)
        {
            return ("INVALID_PASSWORD", "密码至少需要 8 位。");
        }

        return null;
    }

    private static byte[] HashPassword(string password, byte[] salt) =>
        Rfc2898DeriveBytes.Pbkdf2(password, salt, Iterations, HashAlgorithmName.SHA512, HashSize);

    private static bool VerifyPassword(string password, string hashBase64, string saltBase64)
    {
        try
        {
            var expected = Convert.FromBase64String(hashBase64);
            var salt = Convert.FromBase64String(saltBase64);
            var actual = HashPassword(password, salt);
            return CryptographicOperations.FixedTimeEquals(actual, expected);
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static string CreateToken()
    {
        var bytes = RandomNumberGenerator.GetBytes(32);
        return Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    public void Dispose() => _loginGate.Dispose();
}
