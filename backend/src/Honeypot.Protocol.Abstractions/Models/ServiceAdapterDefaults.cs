namespace Honeypot.Protocol.Abstractions.Models;

/// <summary>
/// 平台新建实例的默认元数据；已有实例始终使用自己的配置，不能在升级时被覆盖。
/// HostName 与 ProductVersion 是面向攻击者的诱饵值（用于拟真），不代表任何真实资产或真实版本。
/// </summary>
public sealed record ServiceAdapterDefaults(string Category, string? SystemGroup, string InstanceName,
    int Port, string HostName, string Product, string ProductVersion)
{
    public static ServiceAdapterDefaults For(string key) => key.ToLowerInvariant() switch
    {
        "rdp" => new("system", "Windows", "RDP", 3389, "WIN-7F3A1C2", "Microsoft Terminal Services", "10.0"),
        "ssh" => new("system", "Linux", "SSH", 22, "ubuntu-web-01", "OpenSSH", "9.6p1 Ubuntu-3ubuntu13.5"),
        "smb" => new("system", "Windows", "SMB", 445, "WIN-FILE-01", "Windows File Server", "10.0"),
        "telnet" => new("system", "Linux", "Telnet", 23, "linux-server", "Linux", "1.0"),
        "nfs" => new("system", "Linux", "NFS", 2049, "nfs-server", "NFS", "4.1"),
        "mysql" => new("database", null, "MySQL", 3306, "mysql-prod-01", "MySQL Community Server", "8.0.36"),
        "mssql" => new("database", null, "MSSQL", 1433, "WIN-SQL-01", "Microsoft SQL Server", "15.0.4312.2"),
        "mongodb" => new("database", null, "MongoDB", 27017, "mongo-db-01", "MongoDB", "7.0.5"),
        "postgresql" => new("database", null, "PostgreSQL", 5432, "postgres-db-01", "PostgreSQL", "16.6"),
        "redis" => new("database", null, "Redis", 6379, "redis-cache-01", "Redis", "7.2.6"),
        "oracle" => new("database", null, "Oracle", 1521, "oracle-db-01", "Oracle Database", "19.0.0.0.0"),
        "db2" => new("database", null, "IBM Db2", 50000, "db2inst1", "IBM Db2", "11.5.9"),
        "memcached" => new("database", null, "Memcached", 11211, "memcached-01", "Memcached", "1.6.32"),
        "hbase" => new("database", null, "HBase", 16020, "hbase-region-01", "Apache HBase", "2.5.10"),
        "influxdb" => new("database", null, "InfluxDB", 8086, "influxdb-01", "InfluxDB", "2.7.11"),
        "elasticsearch" => new("database", null, "Elasticsearch", 9200, "elasticsearch-01", "Elasticsearch", "8.17.0"),
        _ => new("other", null, key, 10000, "server-01", key, "1.0"),
    };
}
