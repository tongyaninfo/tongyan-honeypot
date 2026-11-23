using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Honeypot.Api.Data;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace Honeypot.Storage.LoadTest;

/// <summary>构造旧版本合成库，测试真实升级回填；只在当前进程创建的空临时目录中生成密钥。</summary>
internal static class HistoricalFixture
{
    internal static async Task<string> CreateAsync(bool small)
    {
        var directory = Directory.CreateTempSubdirectory("honeypot-storage-replay-").FullName;
        var path = Path.Combine(directory, "honeypot.db");
        var connectionString = new SqliteConnectionStringBuilder { DataSource = path }.ToString();
        var options = new DbContextOptionsBuilder<HoneypotDbContext>().UseSqlite(connectionString).Options;
        await using (var db = new HoneypotDbContext(options))
            await db.GetService<IMigrator>().MigrateAsync("20261115085711_BusinessDataPersistence");

        using var connection = new SqliteConnection(connectionString);
        connection.Open();
        using var transaction = connection.BeginTransaction();
        var connectionCount = small ? 130 : 130_000;
        var evidenceCount = small ? 70 : 70_000;
        var end = DateTimeOffset.UtcNow.AddMinutes(-1);
        var start = end.AddDays(-10);
        using var seed = connection.CreateCommand();
        seed.Transaction = transaction;
        // 旧字段的 JSON 大小、查询键、来源分布均显式构造。不同连接不会共享事件标识。
        seed.CommandText = """
            CREATE TEMP TABLE seed_sessions AS
            WITH RECURSIVE ids(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM ids WHERE n<$sessions)
            SELECT n, printf('hist-%07d',n) AS cid,
                printf('198.51.100.%d',1+(n%220)) AS src,
                $start+CAST(($end-$start)*n/$sessions AS INTEGER) AS ms,
                CASE WHEN n%13<7 THEN 1 ELSE 0 END AS has_auth FROM ids;
            CREATE TEMP TABLE seed_steps AS
            SELECT n,cid,src,ms+seq AS ms,seq,
                printf('hs-%07d-%d',n,seq) AS eid,
                CASE seq WHEN 1 THEN 'ConnectionAccepted' WHEN 2 THEN 'BannerSent'
                  WHEN 3 THEN 'HandshakeReceived' WHEN 4 THEN CASE WHEN has_auth=1 THEN 'AuthenticationAttempted' ELSE 'ProtocolViolation' END
                  ELSE 'SessionClosed' END AS kind,
                CASE WHEN seq=4 AND has_auth=1 THEN 'cred-'||printf('%032x',n) END AS aid
            FROM seed_sessions CROSS JOIN (SELECT 1 AS seq UNION ALL SELECT 2 UNION ALL SELECT 3 UNION ALL SELECT 4 UNION ALL SELECT 5);
            INSERT INTO interaction_events (EventId,ConnectionId,Sequence,OccurredAtUtcTicks,ReceivedAtUnixMs,SourceIp,AdapterKey,EventType,DestinationPort,ActivityPriority,EventJson)
            SELECT eid,cid,seq,ms*10000+621355968000000000,ms,src,'redis',kind,6379,
                CASE kind WHEN 'ConnectionAccepted' THEN 1 WHEN 'AuthenticationAttempted' THEN 4 WHEN 'ProtocolViolation' THEN 2 ELSE 0 END,
                json_object('EventId',eid,'ConnectionId',cid,'Sequence',seq,'EventType',kind,
                    'OccurredAtUtc',strftime('%Y-%m-%dT%H:%M:%fZ',ms/1000.0,'unixepoch'),'SourceIp',src,'SourcePort',10000+n%50000,
                    'DestinationIp','192.0.2.1','DestinationPort',6379,'ListenerId','hist-listener','ServiceInstanceId','hist-instance',
                    'AdapterKey','redis','ProfileId','hist-profile','Transport','tcp','Stage',kind,
                    'Outcome',CASE WHEN aid IS NOT NULL THEN 'failure' ELSE 'observed' END,'PayloadSummary',$padding,
                    'Username',CASE WHEN aid IS NOT NULL THEN 'fixture' END,'CredentialArtifactId',aid,
                    'AuthenticationMethod',CASE WHEN aid IS NOT NULL THEN 'AUTH' END,
                    'CredentialCaptureStatus',CASE WHEN aid IS NOT NULL THEN 'Captured' END,
                    'AuthenticationFailureCode',CASE WHEN aid IS NOT NULL THEN 'WRONGPASS' END,
                    'MaterialType',CASE WHEN aid IS NOT NULL THEN 'Plaintext' END)
            FROM seed_steps;
            INSERT INTO report_events(EventId,OccurredAtUnixMs,EventType,SourceIp,AdapterKey,DestinationPort,Username,AuthenticationMethod,
                IsAuthenticationFailure,RiskSignal,EvidenceKind,CredentialArtifactId,CaptureTruncated)
            SELECT eid,ms,lower(kind),src,'redis',6379,CASE WHEN aid IS NULL THEN '' ELSE 'fixture' END,
                CASE WHEN aid IS NULL THEN '' ELSE 'AUTH' END,aid IS NOT NULL,'low',CASE WHEN aid IS NULL THEN 'none' ELSE 'Plaintext' END,aid,0
            FROM seed_steps;
            INSERT INTO report_source_first_seen(SourceIp,FirstSeenAtUnixMs) SELECT src,min(ms) FROM seed_sessions GROUP BY src;
            """;
        seed.Parameters.AddWithValue("$sessions", connectionCount);
        seed.Parameters.AddWithValue("$start", start.ToUnixTimeMilliseconds());
        seed.Parameters.AddWithValue("$end", end.ToUnixTimeMilliseconds());
        seed.Parameters.AddWithValue("$padding", new string('h', 245));
        seed.ExecuteNonQuery();

        var keyDirectory = Path.Combine(directory, "credential-evidence-keys");
        if (OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("该隔离压测夹具使用 Unix 私有文件权限。");
        Directory.CreateDirectory(keyDirectory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        var key = RandomNumberGenerator.GetBytes(64);
        using (var keyFile = new FileStream(Path.Combine(keyDirectory, "evidence-v1.key"), new FileStreamOptions
        {
            Mode = FileMode.CreateNew,
            Access = FileAccess.Write,
            UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite
        }))
            keyFile.Write(key);
        var keyId = Convert.ToHexString(SHA256.HashData(key));
        using var aes = new AesGcm(key.AsSpan(0, 32), 16);
        using var fingerprint = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, key.AsSpan(32));
        foreach (var field in new[] { "redis", "fixture", "synthetic" })
        {
            var data = Encoding.UTF8.GetBytes(field);
            var size = new byte[4];
            System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(size, data.Length);
            fingerprint.AppendData(size);
            fingerprint.AppendData(data);
        }
        var group = Convert.ToHexString(fingerprint.GetHashAndReset());
        CryptographicOperations.ZeroMemory(key);
        var content = Encoding.UTF8.GetBytes("{\"username\":\"fixture\",\"password\":\"synthetic\",\"padding\":\"" + new string('x', 1024) + "\"}");
        var ciphertext = new byte[content.Length];
        var tag = new byte[16];
        using var insert = connection.CreateCommand();
        insert.Transaction = transaction;
        insert.CommandText = """
            INSERT INTO credential_evidence(ArtifactId,ConnectionId,EventId,SourceIp,AdapterKey,MaterialType,CapturedAtUtcTicks,RetentionUntilUtcTicks,KeyId,
                ContentBytes,Nonce,Tag,Ciphertext,PasswordBookFingerprint,PasswordBookUsername,PasswordBookOccurredAtUtcTicks)
            VALUES($id,$cid,$eid,$src,'redis','Plaintext',$captured,$until,$key,$len,$nonce,$tag,$cipher,$group,'fixture',$captured)
            """;
        foreach (var name in new[] { "$id", "$cid", "$eid", "$src", "$key", "$group" }) insert.Parameters.Add(name, SqliteType.Text);
        foreach (var name in new[] { "$captured", "$until", "$len" }) insert.Parameters.Add(name, SqliteType.Integer);
        foreach (var name in new[] { "$nonce", "$tag", "$cipher" }) insert.Parameters.Add(name, SqliteType.Blob);
        insert.Parameters["$key"].Value = keyId;
        insert.Parameters["$group"].Value = group;
        insert.Parameters["$len"].Value = content.Length;
        var added = 0;
        for (var n = 1; n <= connectionCount; n++)
        {
            if (n % 13 >= 7) continue;
            var aid = $"cred-{n:x32}";
            var cid = $"hist-{n:D7}";
            var eid = $"hs-{n:D7}-4";
            var src = $"198.51.100.{1 + n % 220}";
            var ms = start.ToUnixTimeMilliseconds() + (end.ToUnixTimeMilliseconds() - start.ToUnixTimeMilliseconds()) * n / connectionCount + 4;
            var captured = DateTimeOffset.FromUnixTimeMilliseconds(ms);
            var until = captured.AddDays(30);
            var nonce = RandomNumberGenerator.GetBytes(12);
            var aad = FormattableString.Invariant($"Honeypot.CredentialEvidence.v1\n{keyId}\n{aid}\n{cid}\n{eid}\n{src}\nredis\nPlaintext\n{captured.UtcTicks}\n{until.UtcTicks}");
            aes.Encrypt(nonce, content, ciphertext, tag, Encoding.UTF8.GetBytes(aad));
            insert.Parameters["$id"].Value = aid;
            insert.Parameters["$cid"].Value = cid;
            insert.Parameters["$eid"].Value = eid;
            insert.Parameters["$src"].Value = src;
            insert.Parameters["$captured"].Value = captured.UtcTicks;
            insert.Parameters["$until"].Value = until.UtcTicks;
            insert.Parameters["$nonce"].Value = nonce;
            insert.Parameters["$tag"].Value = tag;
            insert.Parameters["$cipher"].Value = ciphertext;
            insert.ExecuteNonQuery();
            added++;
        }
        if (added != evidenceCount) throw new InvalidDataException("合成证据生成数量错误");
        transaction.Commit();
        File.WriteAllText(Path.Combine(directory, "isolated-replay.json"),
            System.Text.Json.JsonSerializer.Serialize(new { connections = connectionCount, events = connectionCount * 5, evidence = added, contentBytes = (long)added * content.Length }));
        return directory;
    }
}
