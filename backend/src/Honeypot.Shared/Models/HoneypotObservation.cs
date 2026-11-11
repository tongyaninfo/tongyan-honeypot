namespace Honeypot.Shared.Models;

/// <summary>
/// 传感器提交的最小观测合同。字段保持克制，避免一期把原始报文直接写入 API。
/// </summary>
public sealed record HoneypotObservation(
    string SourceIp,
    string SensorType,
    int FailedAttempts,
    double Confidence);
