using Microsoft.Extensions.DependencyInjection;
using Honeypot.Protocol.Abstractions.Service;
using Honeypot.Protocols.Ssh;
using Honeypot.Protocols.Rdp;
using Honeypot.Protocols.MySql;
using Honeypot.Protocols.MsSql;
using Honeypot.Protocols.Mongo;
using Honeypot.Protocols.PostgreSql;
using Honeypot.Protocols.Redis;
using Honeypot.Protocols.Oracle;
using Honeypot.Protocols.Db2;
using Honeypot.Protocols.Memcached;
using Honeypot.Protocols.HBase;
using Honeypot.Protocols.InfluxDb;
using Honeypot.Protocols.Elasticsearch;
using Honeypot.Protocols.Telnet;
using Honeypot.Protocols.Smb;
using Honeypot.Protocols.Nfs;

namespace Honeypot.Protocols.Builtin;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddBuiltinProtocolAdapters(this IServiceCollection services)
    {
        services.AddSingleton<IHoneypotServiceAdapter, SshAdapter>();
        services.AddSingleton<IHoneypotServiceAdapter, RdpAdapter>();
        services.AddSingleton<IHoneypotServiceAdapter, MySqlAdapter>();
        services.AddSingleton<IHoneypotServiceAdapter, MsSqlAdapter>();
        services.AddSingleton<IHoneypotServiceAdapter, MongoAdapter>();
        services.AddSingleton<IHoneypotServiceAdapter, PostgreSqlAdapter>();
        services.AddSingleton<IHoneypotServiceAdapter, RedisAdapter>();
        services.AddSingleton<IHoneypotServiceAdapter, OracleAdapter>();
        services.AddSingleton<IHoneypotServiceAdapter, Db2Adapter>();
        services.AddSingleton<IHoneypotServiceAdapter, MemcachedAdapter>();
        services.AddSingleton<IHoneypotServiceAdapter, HBaseAdapter>();
        services.AddSingleton<IHoneypotServiceAdapter, InfluxDbAdapter>();
        services.AddSingleton<IHoneypotServiceAdapter, ElasticsearchAdapter>();
        services.AddSingleton<IHoneypotServiceAdapter, TelnetAdapter>();
        services.AddSingleton<IHoneypotServiceAdapter, SmbAdapter>();
        services.AddSingleton<IHoneypotServiceAdapter, NfsAdapter>();
        return services;
    }

    public static IServiceCollection AddHoneypotBuiltInProtocolAdapters(this IServiceCollection services) =>
        services.AddBuiltinProtocolAdapters();
}
