using System.Text.Json;
using Honeypot.Api.Common;
using Honeypot.Shared.Models;

namespace Honeypot.Api.Service.impl;

/// <summary>通研 IP 适配器：总超时覆盖响应体读取，不重试、不跟随重定向。</summary>
public sealed class TongYanIPLocation(HttpClient client) : IIPLocation, IDisposable
{
    private const int MaximumResponseBytes = 64 * 1024;

    public void Dispose() => client.Dispose();

    public async Task<IPLocationResult> ResolveAsync(string ip, IPLocationSettings settings, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(settings.TimeoutSeconds));
        try
        {
            var uri = new UriBuilder(settings.Protocol, settings.Host, settings.Port, "/")
            {
                Query = $"ip={Uri.EscapeDataString(ip)}&db={Uri.EscapeDataString(settings.Database)}&format=json"
            }.Uri;
            using var request = new HttpRequestMessage(HttpMethod.Get, uri);
            request.Headers.Accept.ParseAdd("application/json");
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, deadline.Token).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode || response.Content.Headers.ContentLength > MaximumResponseBytes) return Failed(ip);
            await using var input = await response.Content.ReadAsStreamAsync(deadline.Token).ConfigureAwait(false);
            using var output = new MemoryStream();
            var buffer = new byte[8192];
            while (true)
            {
                var count = await input.ReadAsync(buffer, deadline.Token).ConfigureAwait(false);
                if (count == 0) break;
                if (output.Length + count > MaximumResponseBytes) return Failed(ip);
                output.Write(buffer, 0, count);
            }
            deadline.Token.ThrowIfCancellationRequested();
            using var document = JsonDocument.Parse(output.GetBuffer().AsMemory(0, (int)output.Length), new JsonDocumentOptions { MaxDepth = 16 });
            return Parse(ip, settings.Database, document.RootElement);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) { return Failed(ip); }
        catch (Exception error) when (error is HttpRequestException or IOException or JsonException or InvalidOperationException)
        {
            // 不将服务地址、上游正文或异常内容带回页面或普通业务日志。
            return Failed(ip);
        }
    }

    private static IPLocationResult Parse(string ip, string database, JsonElement root)
    {
        if (root.ValueKind != JsonValueKind.Object || !root.TryGetProperty("success", out var success) || success.ValueKind != JsonValueKind.True ||
            !root.TryGetProperty("data", out var data) || data.ValueKind != JsonValueKind.Object ||
            !data.TryGetProperty("sources", out var sources) || sources.ValueKind != JsonValueKind.Array ||
            !IPLocationAddress.TryParse(Text(data, "ip"), out var returnedIp) || !IPLocationAddress.TryParse(ip, out var requestedIp) || !returnedIp.Equals(requestedIp))
            return Failed(ip);
        foreach (var source in sources.EnumerateArray())
        {
            if (source.ValueKind != JsonValueKind.Object || !Text(source, "id").Equals(database, StringComparison.OrdinalIgnoreCase)) continue;
            var status = Text(source, "status");
            if (status.Equals("notFound", StringComparison.OrdinalIgnoreCase)) return new(ip, "resolved", "未查询到归属地");
            if (!status.Equals("success", StringComparison.OrdinalIgnoreCase)) return Failed(ip);
            if (!source.TryGetProperty("fields", out var fields) || fields.ValueKind != JsonValueKind.Object) return new(ip, "resolved", "未查询到归属地");
            var result = new IPLocationResult(ip, "resolved", Country: Text(fields, "country"), Province: Text(fields, "region"),
                City: Text(fields, "city"), District: Text(fields, "district"), Isp: Text(fields, "isp"));
            var name = string.Join(" · ", new[] { result.Country, result.Province, result.City, result.District, result.Isp }.Where(value => value.Length > 0).Distinct());
            return result with { DisplayName = name.Length > 0 ? name : "未查询到归属地" };
        }
        return Failed(ip);
    }

    private static string Text(JsonElement element, string name)
    {
        if (!element.TryGetProperty(name, out var property) || property.ValueKind != JsonValueKind.String) return "";
        var text = property.GetString()?.Trim() ?? "";
        return text[..Math.Min(text.Length, 256)];
    }

    private static IPLocationResult Failed(string ip) => new(ip, "failed", "归属地解析失败");
}
