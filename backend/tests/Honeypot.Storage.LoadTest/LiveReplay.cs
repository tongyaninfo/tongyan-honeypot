using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text.Json;
using Honeypot.Engine.Service;
using Honeypot.Protocol.Abstractions.Models;
using Honeypot.Protocol.Abstractions.Service;
using Honeypot.Protocols.Common;
using static Honeypot.Storage.LoadTest.ProtocolMix;
using Microsoft.Extensions.DependencyInjection;

namespace Honeypot.Storage.LoadTest;

internal sealed record ExpectedSession(int Number, string Phase, string ConnectionId, string Source, string Adapter, string[] Kinds);
internal sealed record PhaseResult(string Name, int OfferedSteps, int Connections, double OfferedSeconds, double DrainSeconds,
    object CommitMs, object AcceptMs, object ThreatVisibleMs, int Failures);

internal sealed class Timings
{
    private readonly ConcurrentQueue<double> samples = new();
    public void Record(double milliseconds) => samples.Enqueue(milliseconds);
    public void Add(long started) => samples.Enqueue(Stopwatch.GetElapsedTime(started).TotalMilliseconds);
    public double P95 => Percentile(samples.Order().ToArray(), .95);
    private static double Percentile(double[] ordered, double fraction) => ordered.Length == 0 ? 0 :
        Math.Round(ordered[(int)Math.Ceiling(ordered.Length * fraction) - 1], 2);
    public object Summary()
    {
        var ordered = samples.Order().ToArray();
        return new { count = ordered.Length, p50 = Percentile(ordered, .5), p95 = Percentile(ordered, .95), p99 = Percentile(ordered, .99), max = Percentile(ordered, 1) };
    }
}

internal sealed class LiveReplay(IServiceProvider services)
{
    private readonly IInteractionEventSink sink = services.GetRequiredService<IInteractionEventSink>();
    private readonly IThreatProfileStore threats = services.GetRequiredService<IThreatProfileStore>();
    public List<ExpectedSession> Sessions { get; } = [];
    public ConcurrentDictionary<string, int> Failures { get; } = new();
    public bool Passed { get; private set; } = true;
    private int nextSession;
    internal static string EventId(ExpectedSession session, int sequence) => $"{session.ConnectionId}-s{sequence}";
    internal static string Username(ExpectedSession session) => $"fixture-{session.Number % 97:D2}";
    internal static string Material(ExpectedSession session) => session.Adapter == "rdp" ? "Response" : "Plaintext";
    internal static SessionCloseReason CloseReason(ExpectedSession session)
    {
        if (session.Kinds.Contains("ProtocolViolation")) return SessionCloseReason.ProtocolViolation;
        return session.Kinds.Length == 2 ? SessionCloseReason.ClientClosed : SessionCloseReason.AdapterCompleted;
    }
    internal static byte[] Evidence(ExpectedSession session, int sequence) =>
        Material(session) == "Response" ? JsonSerializer.SerializeToUtf8Bytes(new { sample = $"response-{session.Number}-{sequence}", padding = new string('r', 1200) }) :
        JsonSerializer.SerializeToUtf8Bytes(new { username = Username(session), password = $"sample-{session.Number:D6}-{sequence}", usernameProvided = true });

    public async Task<PhaseResult> RunAsync(string name, int rate, TimeSpan duration)
    {
        var commit = new Timings();
        var accepts = new Timings();
        var visible = new Timings();
        var running = new List<Task>();
        var clock = Stopwatch.StartNew();
        var target = (int)Math.Round(duration.TotalMinutes * rate);
        var offered = 0;
        var sessions = 0;
        var previousFailures = Failures.Values.Sum();
        while (offered < target)
        {
            // 开环发起，按墙钟和发起清单计量；每分钟开头集中发出三秒负载，模拟短时扫描突发。
            var scheduled = offered * 60d / rate;
            var at = Math.Floor(scheduled);
            if (at % 60 < 3) at -= at % 60;
            var delay = TimeSpan.FromSeconds(at) - clock.Elapsed;
            if (delay > TimeSpan.Zero) await Task.Delay(delay);
            running.RemoveAll(task => task.IsCompletedSuccessfully);
            var id = ++nextSession;
            var script = Scripts[(id - 1) % Scripts.Length];
            var kinds = script.Kinds;
            if (target - offered < kinds.Length + 2)
                kinds = Enumerable.Repeat("HandshakeReceived", target - offered - 2).Prepend(Accept).Append(Close).ToArray();
            var session = new ExpectedSession(id, name, $"live-{id:D7}", $"2001:db8::{1 + id % 400:x}", script.Adapter, kinds);
            Sessions.Add(session);
            var submittedAt = Stopwatch.GetTimestamp();
            running.Add(Task.Run(() => RecordSession(session, submittedAt, commit, accepts, visible)));
            offered += kinds.Length;
            sessions++;
        }
        var remaining = duration - clock.Elapsed;
        if (remaining > TimeSpan.Zero) await Task.Delay(remaining);
        var offerSeconds = clock.Elapsed.TotalSeconds;
        await Task.WhenAll(running);
        var drainSeconds = clock.Elapsed.TotalSeconds - offerSeconds;
        var errors = Failures.Values.Sum() - previousFailures;
        Passed &= errors == 0 && accepts.P95 <= 500 && visible.P95 <= 1000 && drainSeconds <= 60;
        return new(name, offered, sessions, Math.Round(offerSeconds, 2), Math.Round(drainSeconds, 2),
            commit.Summary(), accepts.Summary(), visible.Summary(), errors);
    }

    private async Task RecordSession(ExpectedSession session, long submittedAt, Timings commit, Timings accepts, Timings visible)
    {
        var attempt = 0;
        for (var i = 0; i < session.Kinds.Length; i++)
        {
            var kind = session.Kinds[i];
            var sequence = i + 1;
            var auth = kind == Auth;
            var now = DateTimeOffset.UtcNow;
            var item = new InteractionEvent
            {
                EventId = EventId(session, sequence),
                ConnectionId = session.ConnectionId,
                Sequence = sequence,
                EventType = kind,
                OccurredAtUtc = now,
                SourceIp = session.Source,
                SourcePort = 10000 + session.Number % 50000,
                DestinationIp = "192.0.2.1",
                DestinationPort = 10000 + session.Number % 6,
                ListenerId = "local-" + session.Adapter,
                ServiceInstanceId = "fixture-" + session.Adapter,
                AdapterKey = session.Adapter,
                ProfileId = "test",
                Stage = auth ? "authentication" : kind,
                Outcome = kind switch { Auth => "failure", "ProtocolViolation" => "malformed", Close => "completed", _ => "observed" },
                RiskDelta = kind switch { Accept => 1, Auth => 5, _ => 0 },
                Username = auth ? Username(session) : null,
                AuthenticationMethod = auth ? (session.Adapter == "rdp" ? "ntlm" : "password") : null,
                AuthenticationFailureCode = auth ? "denied" : null,
                AuthenticationAttempt = auth ? ++attempt : null,
                MaterialType = auth ? Material(session) : null,
                CloseReason = kind == Close ? CloseReason(session) : null,
            };
            var start = i == 0 ? submittedAt : Stopwatch.GetTimestamp();
            try
            {
                if (auth)
                {
                    var evidence = new CredentialEvidence(session.ConnectionId, item.EventId, item.SourceIp, item.AdapterKey, Material(session),
                        Evidence(session, sequence), now, 30, "utf8-json");
                    var recorded = await CredentialEventRecording.AppendAsync(sink, item, evidence, CancellationToken.None);
                    if (!recorded.Result.Recorded || recorded.Result.IsDuplicate || recorded.Event.CredentialArtifactId is null) throw new InvalidDataException("MISSING_EVIDENCE");
                }
                else
                {
                    var result = await sink.AppendAsync(item);
                    if (!result.Recorded || result.IsDuplicate) throw new InvalidDataException(result.Code);
                }
                commit.Add(start);
                if (i == 0)
                {
                    accepts.Add(start);
                    if (threats.GetByIp(session.Source) is not { } profile || profile.LastSeenUtc < now)
                        throw new InvalidDataException("THREAT_NOT_VISIBLE");
                    visible.Add(submittedAt);
                }
            }
            catch (Exception e)
            {
                var reason = e is InvalidDataException ? e.Message : e.GetType().Name;
                Failures.AddOrUpdate(reason, 1, (_, count) => count + 1);
            }
        }
    }
}
