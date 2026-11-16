using System.Text;
using Honeypot.Api.Common;
using Honeypot.Shared.Models;

namespace Honeypot.Api.Service.impl;

public sealed class ConnectionMapPublicIpProbe(HttpClient client) : IDisposable
{
    private const int MaximumBytes = 128;

    public async Task<string?> DiscoverAsync(IPLocationSettings settings, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!settings.Enabled || !IPLocationSettingsValidation.TryNormalize(settings, out var selected)) return null;

        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(selected.TimeoutSeconds));
        try
        {
            // 只访问当前已配置的同源根路径，不接收浏览器地址、转发头或额外查询参数。
            using var request = new HttpRequestMessage(HttpMethod.Get, new UriBuilder(selected.Protocol, selected.Host, selected.Port, "/").Uri);
            request.Headers.Accept.ParseAdd("text/plain");
            request.Headers.CacheControl = new() { NoCache = true, NoStore = true };
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, deadline.Token);
            if (!response.IsSuccessStatusCode || response.Content.Headers.ContentLength > MaximumBytes ||
                !string.Equals(response.Content.Headers.ContentType?.MediaType, "text/plain", StringComparison.OrdinalIgnoreCase) ||
                response.Content.Headers.ContentEncoding.Count != 0)
                return null;

            await using var body = await response.Content.ReadAsStreamAsync(deadline.Token);
            var bytes = new byte[MaximumBytes + 1];
            var count = await body.ReadAtLeastAsync(bytes, bytes.Length, false, deadline.Token);
            if (count > MaximumBytes) return null;
            var address = Encoding.UTF8.GetString(bytes, 0, count).Trim();
            return IPLocationAddress.Classify(address, out var normalized) is null ? normalized : null;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) { return null; }
        catch (Exception error) when (error is HttpRequestException or IOException or InvalidOperationException or FormatException)
        {
            // 探测失败保留既有地图状态，不输出解析正文、主机或地址。
            return null;
        }
    }

    public void Dispose() => client.Dispose();
}
