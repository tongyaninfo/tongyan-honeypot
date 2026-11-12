using Honeypot.Api.Models;

namespace Honeypot.Api.Service;

public interface IMcpStore
{
    Task<McpSettings> GetSettingsAsync(CancellationToken cancellationToken = default);
    Task<McpAuthenticationResult> AuthenticateAsync(string token, CancellationToken cancellationToken = default);
    Task TouchKeyAsync(string id, CancellationToken cancellationToken = default);
    Task<string> BeginAuditAsync(McpAuditEntry entry, CancellationToken cancellationToken = default);
    Task CompleteAuditAsync(string id, McpAuditEntry entry, CancellationToken cancellationToken = default);
    Task RecordAuditAsync(McpAuditEntry entry, CancellationToken cancellationToken = default);
}

public sealed class McpAuditHealth
{
    private int _writeUnavailable;
    private int _retentionUnavailable;
    private long _droppedCount;

    public bool IsAvailable => Volatile.Read(ref _writeUnavailable) == 0 && Volatile.Read(ref _retentionUnavailable) == 0;
    public long DroppedCount => Interlocked.Read(ref _droppedCount);
    public void ReportFailure() => Volatile.Write(ref _writeUnavailable, 1);
    public void ReportSuccess() => Volatile.Write(ref _writeUnavailable, 0);
    public void ReportDrop() => Interlocked.Increment(ref _droppedCount);
    internal void SetRetentionAvailable(bool available) => Volatile.Write(ref _retentionUnavailable, available ? 0 : 1);
}
