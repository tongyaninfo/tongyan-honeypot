using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Honeypot.Api.Common;

internal static class PasswordBookProjection
{
    internal sealed record Candidate(string Fingerprint, string EventUsername, bool AmbiguousRedisUsername, bool AmbiguousInfluxPassword)
    {
        public bool IsCompatibleWith(string? method) =>
            !(AmbiguousRedisUsername && (string.IsNullOrEmpty(method) || method.Equals("AUTH", StringComparison.OrdinalIgnoreCase))) &&
            !(AmbiguousInfluxPassword && (string.IsNullOrEmpty(method) || method.Equals("HTTP-Query", StringComparison.OrdinalIgnoreCase)));
    }

    public static Candidate? ReadCandidate(ReadOnlyMemory<byte> content, string adapterKey, string materialType, byte[] key)
    {
        if (!IsCandidateMaterialType(materialType)) return null;

        try
        {
            using var document = JsonDocument.Parse(content);
            var fields = document.RootElement;
            if (fields.ValueKind != JsonValueKind.Object ||
                !fields.TryGetProperty("username", out var usernameField) || usernameField.ValueKind != JsonValueKind.String ||
                !fields.TryGetProperty("password", out var passwordField) || passwordField.ValueKind != JsonValueKind.String)
                return null;

            var usernameProvided = ReadPresence(fields, "usernameProvided");
            var passwordProvided = ReadPresence(fields, "passwordProvided");
            if (usernameProvided is false || passwordProvided is false) return null;

            var username = usernameField.GetString()!;
            var eventUsername = InteractionEventSanitizer.SanitizeUsername(username);
            if (string.IsNullOrEmpty(eventUsername)) return null;

            var password = passwordField.GetString()!;
            var adapter = adapterKey.ToLowerInvariant();
            using var digest = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, key);
            // 带长度的 UTF-8 字段保持原始账号和密码的大小写、空格与分组边界。
            AppendField(digest, adapter);
            AppendField(digest, username);
            AppendField(digest, password);
            return new(Convert.ToHexString(digest.GetHashAndReset()), eventUsername,
                adapter == "redis" && username == "default" && usernameProvided is null,
                adapter == "influxdb" && password.Length == 0 && passwordProvided is null);
        }
        catch (Exception exception) when (exception is JsonException or InvalidOperationException)
        {
            // 无法解析的材料继续由证据仓库加密留存，但不参与密码簿。
            return null;
        }
    }

    internal static bool IsCandidateMaterialType(string materialType) =>
        string.Equals(materialType, "Plaintext", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(materialType, "Decrypted", StringComparison.OrdinalIgnoreCase);

    // SQLite 的 lower() 只折叠 ASCII。搜索参数和内存查询遵从同一规则，其余字符按字面匹配。
    internal static string FoldSearchText(string text) => text.AsSpan().IndexOfAnyInRange('A', 'Z') < 0 ? text :
        string.Create(text.Length, text, static (destination, source) =>
        {
            for (var index = 0; index < source.Length; index++)
            {
                var value = source[index];
                destination[index] = value is >= 'A' and <= 'Z' ? (char)(value + ('a' - 'A')) : value;
            }
        });

    private static bool? ReadPresence(JsonElement value, string name) =>
        value.TryGetProperty(name, out var field) ? field.ValueKind == JsonValueKind.True : null;

    private static void AppendField(IncrementalHash digest, string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        Span<byte> length = stackalloc byte[4];
        BinaryPrimitives.WriteInt32BigEndian(length, bytes.Length);
        try
        {
            digest.AppendData(length);
            digest.AppendData(bytes);
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
}
