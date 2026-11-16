namespace Honeypot.Api.Models;

/// <summary>密码簿的分页摘要；密码原文仅由已有的单条证据接口返回。</summary>
public sealed record PasswordBookRow(
    string Username,
    string AdapterKey,
    int AuthenticationCount,
    DateTimeOffset LastUsedAtUtc,
    string CredentialArtifactId);
