using System.Text.Json;
using Honeypot.Protocol.Abstractions.Models;
using Honeypot.Protocol.Abstractions.Service;
using Honeypot.Protocols.Builtin;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Honeypot.Runtime.Tests;

public sealed class ServiceCatalogDefaultsTests
{
    [Fact]
    public void RegisteredAdaptersExposeConventionalDefaultsWithoutTdsqlOrDuplicateKeys()
    {
        var services = new ServiceCollection().AddBuiltinProtocolAdapters();
        using var provider = services.BuildServiceProvider();
        var adapters = provider.GetServices<IHoneypotServiceAdapter>().Select(x => x.Descriptor).ToArray();
        Assert.Equal(16, adapters.Length);
        Assert.Equal(16, adapters.Select(x => x.AdapterKey).Distinct().Count());
        Assert.DoesNotContain(adapters, x => x.AdapterKey.Contains("tdsql", StringComparison.OrdinalIgnoreCase));
        var ports = new Dictionary<string, int>
        {
            ["postgresql"] = 5432, ["redis"] = 6379, ["oracle"] = 1521, ["db2"] = 50000,
            ["memcached"] = 11211, ["hbase"] = 16020, ["influxdb"] = 8086, ["elasticsearch"] = 9200,
            ["telnet"] = 23, ["smb"] = 445, ["nfs"] = 2049,
        };
        foreach (var (key, port) in ports)
        {
            var descriptor = Assert.Single(adapters, x => x.AdapterKey == key);
            Assert.Equal(port, descriptor.DefaultPort);
            Assert.False(string.IsNullOrWhiteSpace(descriptor.DefaultInstanceName));
            using var json = JsonDocument.Parse(JsonSerializer.Serialize(descriptor, new JsonSerializerOptions(JsonSerializerDefaults.Web)));
            Assert.Equal(port, json.RootElement.GetProperty("defaultPort").GetInt32());
        }
        Assert.Equal(5, adapters.Count(x => x.Category == "system"));
        Assert.Equal(11, adapters.Count(x => x.Category == "database"));
    }
}
