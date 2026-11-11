using Xunit;
using Honeypot.Engine.Models;
using Honeypot.Engine.Service.impl;
using Honeypot.Shared.Models;

namespace Honeypot.Engine.Tests;

public sealed class ThreatDecisionEngineTests
{
    private readonly ThreatDecisionEngine _engine = new();

    [Fact]
    public void RepeatedHighConfidenceFailuresShouldBlock()
    {
        var result = _engine.Evaluate(new HoneypotObservation("192.0.2.10", "ssh", 5, 0.92));

        Assert.Equal(ThreatDecision.Block, result.Decision);
    }

    [Fact]
    public void SingleSuspiciousSignalShouldBeObserved()
    {
        var result = _engine.Evaluate(new HoneypotObservation("192.0.2.10", "http", 1, 0.4));

        Assert.Equal(ThreatDecision.Observe, result.Decision);
    }

    [Fact]
    public void EmptySourceShouldBeIgnored()
    {
        var result = _engine.Evaluate(new HoneypotObservation("", "ssh", 10, 1));

        Assert.Equal(ThreatDecision.Ignore, result.Decision);
    }
}
