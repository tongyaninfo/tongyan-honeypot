namespace Honeypot.Protocol.Abstractions.Models;

public sealed record EventAppendResult(bool Recorded, bool Degraded, string Code, string Message)
{
    /// <summary>重复记录已经存在，但不能再次触发实时广播、日志外发或其他副作用。</summary>
    public bool IsDuplicate { get; init; }

    public static EventAppendResult Accepted(string message = "event accepted") =>
        new(true, false, "RECORDED", message);

    public static EventAppendResult Duplicate(string message = "duplicate event ignored") =>
        Accepted(message) with { IsDuplicate = true };

    public static EventAppendResult DegradedResult(string code, string message) =>
        new(false, true, code, message);
}
