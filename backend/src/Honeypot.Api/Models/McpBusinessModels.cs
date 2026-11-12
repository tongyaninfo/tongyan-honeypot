using System.Text.Json;

namespace Honeypot.Api.Models;

public sealed record McpToolDescriptor(string Name, string DisplayName, string Group, string GroupLabel,
    string Description, bool IsWrite, bool RequiresInstanceScope, JsonElement InputSchema);

public sealed record McpToolCallContext(string KeyId, IReadOnlyDictionary<string, string> InstanceBindingFingerprints);
