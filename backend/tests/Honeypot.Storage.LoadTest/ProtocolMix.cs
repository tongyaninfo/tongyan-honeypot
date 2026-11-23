namespace Honeypot.Storage.LoadTest;

/// <summary>使用现场窗口的分组计数生成合成连接，既不读取原文，也不对网络发送协议报文。</summary>
internal static class ProtocolMix
{
    internal const string Accept = "ConnectionAccepted", Close = "SessionClosed", Auth = "AuthenticationAttempted";
    internal sealed record Script(string Adapter, string[] Kinds);
    private sealed record Counts(string Adapter, int Steps, int Connections, int Authentications, int Violations);
    // 2026-11-19 14:47:11–18:17:00 +08:00。按已成功记录的步骤统计；窗口边界可能切过连接。
    private static readonly Counts[] Observed =
    [
        new("db2", 5, 3, 0, 0),
        new("influxdb", 13, 5, 0, 1),
        new("memcached", 119, 47, 0, 24),
        new("mongodb", 227, 81, 0, 56),
        new("mssql", 248, 59, 0, 46),
        new("mysql", 129, 34, 0, 24),
        new("nfs", 25, 11, 0, 2),
        new("oracle", 11, 6, 0, 0),
        new("postgresql", 168, 63, 11, 3),
        new("rdp", 6158, 927, 780, 92),
        new("redis", 57, 20, 12, 2),
        new("smb", 171, 66, 0, 33),
        new("ssh", 6304, 1413, 159, 799),
        new("telnet", 1295, 433, 424, 0)
    ];
    internal static readonly Script[] Scripts = Create();
    private static Script[] Create()
    {
        var random = new Random(19019);
        var sessions = new List<Script>();
        foreach (var mix in Observed)
        {
            var schedule = Enumerable.Range(0, mix.Connections).Select(_ => new List<string> { Accept }).ToArray();
            var normal = Math.Max(0, mix.Steps - mix.Connections * 2 - mix.Authentications - mix.Violations);
            string[] stages = mix.Adapter switch
            {
                "rdp" => ["X224ConnectionConfirmSent", "TlsHandshakeCompleted", "CredSspChallengeSent", "HandshakeReceived"],
                "mssql" => ["HandshakeReceived", "PreloginResponseSent", "TlsHandshakeCompleted"],
                "ssh" => ["BannerSent", "HandshakeReceived", "AuthenticationMethodsRequested"],
                _ => ["HandshakeReceived", "BannerSent"]
            };
            for (var i = 0; i < normal; i++)
            {
                var session = schedule[i % mix.Connections];
                var stage = stages[(i / mix.Connections + i) % stages.Length];
                session.Add(stage);
            }
            // 随机分配但固定种子，保留同连接多次认证与即断连接。
            for (var i = 0; i < mix.Authentications; i++) schedule[random.Next(mix.Connections)].Add(Auth);
            for (var i = 0; i < mix.Violations; i++) schedule[random.Next(mix.Connections)].Add("ProtocolViolation");
            foreach (var steps in schedule)
            {
                steps.Add(Close);
                sessions.Add(new(mix.Adapter, steps.ToArray()));
            }
        }
        var shuffled = sessions.ToArray();
        random.Shuffle(shuffled);
        return shuffled;
    }
}
