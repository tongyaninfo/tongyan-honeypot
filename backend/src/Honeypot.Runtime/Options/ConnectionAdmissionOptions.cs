namespace Honeypot.Runtime.Options;

/// <summary>进程内所有蜜罐 TCP 监听共享的接纳预算。</summary>
public sealed class ConnectionAdmissionOptions
{
    public const string SectionName = "Honeypot:ConnectionAdmission";

    public int MaxConcurrentConnections { get; set; } = 512;
    public int MaxConcurrentConnectionsPerSource { get; set; } = 24;
    public int MaxNewConnectionsPerSecond { get; set; } = 120;
    public int MaxNewConnectionsPerSourcePerSecond { get; set; } = 12;
    public int MaxTrackedSources { get; set; } = 8192;
    public int AcceptedEventTimeoutSeconds { get; set; } = 3;

    internal bool IsValid() => MaxConcurrentConnections > 0 && MaxConcurrentConnectionsPerSource > 0 &&
        MaxNewConnectionsPerSecond > 0 && MaxNewConnectionsPerSourcePerSecond > 0 && MaxTrackedSources > 0 &&
        AcceptedEventTimeoutSeconds is >= 1 and <= 60;
}
