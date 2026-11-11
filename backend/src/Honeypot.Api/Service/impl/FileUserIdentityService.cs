using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Honeypot.Api.Models;
using Honeypot.Api.Service;
using Honeypot.Shared.Models;

namespace Honeypot.Api.Service.impl;

/// <summary>文件持久化用户服务。首个管理员必须通过初始化接口创建。</summary>
public sealed class FileUserIdentityService : IUserIdentityService
{
    private const int SaltSize = 16;
    private const int HashSize = 32;
    private const int Iterations = 600_000;
    private static readonly Regex UsernamePattern = new("^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$", RegexOptions.Compiled);
    private readonly object _sync = new();
    private readonly string _usersFilePath;
    private readonly TimeSpan _sessionLifetime;
    private readonly ConcurrentDictionary<string, (AuthenticatedUser User, DateTimeOffset ExpiresAtUtc)> _sessions = new(StringComparer.Ordinal);
    private readonly JsonSerializerOptions _jsonOptions = new(JsonSerializerDefaults.Web) { WriteIndented = true };
    private List<UserAccount> _users;

    public FileUserIdentityService(IConfiguration configuration, IWebHostEnvironment environment, ISyslogPublisher? logs = null)
    {
        var dataDirectory = configuration["Honeypot:DataDirectory"];
        if (string.IsNullOrWhiteSpace(dataDirectory))
        {
            dataDirectory = Path.Combine(environment.ContentRootPath, "data");
        }

        Directory.CreateDirectory(dataDirectory);
        _usersFilePath = Path.Combine(dataDirectory, "users.json");
        _sessionLifetime = TimeSpan.FromHours(configuration.GetValue("Honeypot:SessionLifetimeHours", 8));
        try { _users = LoadUsers(); }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or InvalidOperationException)
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

    public Task<LoginResult?> LoginAsync(string username, string password, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        UserAccount? account;
        lock (_sync)
        {
            account = _users.FirstOrDefault(item => item.Username.Equals(username.Trim(), StringComparison.OrdinalIgnoreCase));
        }

        if (account is null || account.Disabled || !VerifyPassword(password, account.PasswordHash, account.PasswordSalt))
        {
            return Task.FromResult<LoginResult?>(null);
        }

        var user = new AuthenticatedUser(account.UserId, account.Username, account.Roles);
        var expiresAt = DateTimeOffset.UtcNow.Add(_sessionLifetime);
        var token = CreateToken();
        _sessions[token] = (user, expiresAt);
        return Task.FromResult<LoginResult?>(new LoginResult(token, expiresAt, user));
    }

    public bool TryAuthenticate(string accessToken, out AuthenticatedUser? user)
    {
        user = null;
        if (string.IsNullOrWhiteSpace(accessToken) || !_sessions.TryGetValue(accessToken, out var session))
        {
            return false;
        }

        if (session.ExpiresAtUtc <= DateTimeOffset.UtcNow)
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
}
