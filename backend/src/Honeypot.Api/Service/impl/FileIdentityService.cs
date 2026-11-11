using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text.Json;
using Honeypot.Api.Models;

namespace Honeypot.Api.Service.impl;

/// <summary>
/// 文件用户存储：首次启动没有管理员，必须通过初始化接口创建首个管理员。
/// 生产部署应把数据目录放在受控卷，并替换为集中身份服务。
/// </summary>
public sealed class FileIdentityService : IIdentityService
{
    private sealed record StoredUser(
        string UserId,
        string Username,
        string PasswordHash,
        string PasswordSalt,
        string[] Roles,
        DateTimeOffset CreatedAtUtc);

    private sealed record StoredSession(string Token, AuthenticatedUser User, DateTimeOffset ExpiresAtUtc);

    private readonly string _usersFile;
    private readonly ConcurrentDictionary<string, StoredSession> _sessions = new(StringComparer.Ordinal);
    private readonly SemaphoreSlim _fileLock = new(1, 1);
    private readonly JsonSerializerOptions _jsonOptions = new(JsonSerializerDefaults.Web) { WriteIndented = true };
    private List<StoredUser> _users;

    public FileIdentityService(IConfiguration configuration, IHostEnvironment environment)
    {
        var configuredDirectory = configuration["Honeypot:DataDirectory"];
        var dataDirectory = string.IsNullOrWhiteSpace(configuredDirectory)
            ? Path.Combine(environment.ContentRootPath, "data")
            : configuredDirectory;
        Directory.CreateDirectory(dataDirectory);
        _usersFile = Path.Combine(dataDirectory, "users.json");
        _users = LoadUsers();
    }

    public bool IsInitialized => _users.Count > 0;

    public SetupStatus GetSetupStatus() => new(IsInitialized, !IsInitialized);

    public async Task<UserInfo> InitializeFirstAdminAsync(string username, string password, CancellationToken cancellationToken = default)
    {
        ValidateCredentials(username, password);
        await _fileLock.WaitAsync(cancellationToken);
        try
        {
            _users = LoadUsers();
            if (_users.Count > 0)
            {
                throw new InvalidOperationException("INITIAL_SETUP_COMPLETED");
            }

            var user = CreateStoredUser(username, password, new[] { "admin" });
            _users.Add(user);
            await SaveUsersAsync(cancellationToken);
            return ToUserInfo(user);
        }
        finally
        {
            _fileLock.Release();
        }
    }

    public async Task<UserInfo> CreateUserAsync(string username, string password, IReadOnlyCollection<string> roles, CancellationToken cancellationToken = default)
    {
        ValidateCredentials(username, password);
        var normalized = NormalizeUsername(username);
        await _fileLock.WaitAsync(cancellationToken);
        try
        {
            _users = LoadUsers();
            if (_users.Any(item => item.Username.Equals(normalized, StringComparison.OrdinalIgnoreCase)))
            {
                throw new InvalidOperationException("USER_ALREADY_EXISTS");
            }

            var safeRoles = roles.Count == 0 ? new[] { "analyst" } : roles.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
            var user = CreateStoredUser(normalized, password, safeRoles);
            _users.Add(user);
            await SaveUsersAsync(cancellationToken);
            return ToUserInfo(user);
        }
        finally
        {
            _fileLock.Release();
        }
    }

    public Task<LoginResult?> LoginAsync(string username, string password, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var normalized = NormalizeUsername(username);
        var stored = _users.FirstOrDefault(item => item.Username.Equals(normalized, StringComparison.OrdinalIgnoreCase));
        if (stored is null || !VerifyPassword(password, stored.PasswordSalt, stored.PasswordHash))
        {
            return Task.FromResult<LoginResult?>(null);
        }

        var token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        var expiresAt = DateTimeOffset.UtcNow.AddHours(8);
        var userInfo = ToUserInfo(stored);
        var user = new AuthenticatedUser(userInfo.UserId, userInfo.Username, userInfo.Roles.ToArray());
        _sessions[token] = new StoredSession(token, user, expiresAt);
        return Task.FromResult<LoginResult?>(new LoginResult(token, expiresAt, user));
    }

    public UserInfo? ValidateToken(string? accessToken)
    {
        if (string.IsNullOrWhiteSpace(accessToken) || !_sessions.TryGetValue(accessToken, out var session))
        {
            return null;
        }

        if (session.ExpiresAtUtc <= DateTimeOffset.UtcNow)
        {
            _sessions.TryRemove(accessToken, out _);
            return null;
        }

        return new UserInfo(session.User.UserId, session.User.Username, session.User.Roles, DateTimeOffset.UtcNow);
    }

    public void Logout(string? accessToken)
    {
        if (!string.IsNullOrWhiteSpace(accessToken))
        {
            _sessions.TryRemove(accessToken, out _);
        }
    }

    public IReadOnlyCollection<UserInfo> GetUsers() => _users.Select(ToUserInfo).ToArray();

    private List<StoredUser> LoadUsers()
    {
        if (!File.Exists(_usersFile))
        {
            return new List<StoredUser>();
        }

        try
        {
            return JsonSerializer.Deserialize<List<StoredUser>>(File.ReadAllText(_usersFile), _jsonOptions) ?? new List<StoredUser>();
        }
        catch (JsonException)
        {
            throw new InvalidOperationException("USER_STORE_INVALID");
        }
    }

    private async Task SaveUsersAsync(CancellationToken cancellationToken)
    {
        var temporaryFile = $"{_usersFile}.{Guid.NewGuid():N}.tmp";
        await File.WriteAllTextAsync(temporaryFile, JsonSerializer.Serialize(_users, _jsonOptions), cancellationToken);
        File.Move(temporaryFile, _usersFile, true);
    }

    private static StoredUser CreateStoredUser(string username, string password, string[] roles)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        var hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, 120_000, HashAlgorithmName.SHA512, 64);
        return new StoredUser($"usr-{Guid.NewGuid():N}", NormalizeUsername(username), Convert.ToBase64String(hash), Convert.ToBase64String(salt), roles, DateTimeOffset.UtcNow);
    }

    private static bool VerifyPassword(string password, string encodedSalt, string encodedHash)
    {
        var salt = Convert.FromBase64String(encodedSalt);
        var expected = Convert.FromBase64String(encodedHash);
        var actual = Rfc2898DeriveBytes.Pbkdf2(password, salt, 120_000, HashAlgorithmName.SHA512, expected.Length);
        return CryptographicOperations.FixedTimeEquals(actual, expected);
    }

    private static UserInfo ToUserInfo(StoredUser user) => new(user.UserId, user.Username, user.Roles, user.CreatedAtUtc);

    private static string NormalizeUsername(string username) => username.Trim();

    private static void ValidateCredentials(string username, string password)
    {
        if (string.IsNullOrWhiteSpace(username) || username.Trim().Length < 3 || username.Trim().Length > 64)
        {
            throw new ArgumentException("USERNAME_INVALID");
        }

        if (string.IsNullOrWhiteSpace(password) || password.Length < 10)
        {
            throw new ArgumentException("PASSWORD_TOO_WEAK");
        }
    }
}
