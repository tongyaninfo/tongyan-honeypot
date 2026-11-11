namespace Honeypot.Api.Data;

/// <summary>本机 SQLite 数据库路径配置。</summary>
public static class HoneypotDbOptions
{
    public static string ResolveDataDirectory(IConfiguration configuration, IHostEnvironment environment)
    {
        var configuredDirectory = configuration["Honeypot:DataDirectory"];
        var dataDirectory = string.IsNullOrWhiteSpace(configuredDirectory)
            ? Path.Combine(environment.ContentRootPath, "data")
            : configuredDirectory;
        Directory.CreateDirectory(dataDirectory);
        return dataDirectory;
    }

    public static string ResolveDatabasePath(IConfiguration configuration, IHostEnvironment environment) =>
        Path.Combine(ResolveDataDirectory(configuration, environment), "honeypot.db");
}
