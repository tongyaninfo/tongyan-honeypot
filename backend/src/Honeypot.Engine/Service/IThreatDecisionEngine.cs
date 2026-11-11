using Honeypot.Engine.Models;
using Honeypot.Shared.Models;

namespace Honeypot.Engine.Service;

public interface IThreatDecisionEngine
{
    ThreatDecisionResult Evaluate(HoneypotObservation observation);
}
