using Honeypot.Engine.Models;
using Honeypot.Shared.Models;

namespace Honeypot.Engine.Service.impl;

/// <summary>
/// 一期最小判定器：只根据受控字段做确定性判断，不读取网络、数据库或宿主状态。
/// </summary>
public sealed class ThreatDecisionEngine : IThreatDecisionEngine
{
    public ThreatDecisionResult Evaluate(HoneypotObservation observation)
    {
        ArgumentNullException.ThrowIfNull(observation);

        if (string.IsNullOrWhiteSpace(observation.SourceIp) ||
            string.IsNullOrWhiteSpace(observation.SensorType))
        {
            return Result(ThreatDecision.Ignore, "观测来源或传感器类型为空");
        }

        if (observation.FailedAttempts >= 5 && observation.Confidence >= 0.8)
        {
            return Result(ThreatDecision.Block, "失败尝试次数和置信度同时达到阻断阈值");
        }

        if (observation.FailedAttempts > 0 || observation.Confidence >= 0.5)
        {
            return Result(ThreatDecision.Observe, "观测具备可疑信号，等待更多证据");
        }

        return Result(ThreatDecision.Ignore, "当前观测未达到可疑阈值");
    }

    private static ThreatDecisionResult Result(ThreatDecision decision, string reason) =>
        new(decision, reason, DateTimeOffset.UtcNow);
}
