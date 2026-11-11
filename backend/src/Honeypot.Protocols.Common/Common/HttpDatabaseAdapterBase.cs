using System.Net.Security;
using System.Security.Authentication;
using System.Text;
using System.Text.Json;
using Honeypot.Protocol.Abstractions.Models;
using Honeypot.Protocol.Abstractions.Service;

namespace Honeypot.Protocols.Common;

/// <summary>HTTP 数据库的认证失败公共路径；不记录请求 URL、正文或认证头到普通事件。</summary>
public abstract class HttpDatabaseAdapterBase : ProtocolAdapterBase
{
    protected abstract HttpAuthenticationMaterial? Authentication(ProtocolHttpRequest request, ServiceProfile profile);
    protected abstract ProtocolHttpResponse Response(ProtocolHttpRequest request, ServiceProfile profile, bool attempted);

    public override async ValueTask HandleAsync(IHoneypotSession session, ProtocolSessionContext context, ServiceProfile profile,
        IInteractionEventSink eventSink, CancellationToken cancellationToken = default)
    {
        await using var connection = new ProtocolHttpConnection(session, profile);
        var closeReason = SessionCloseReason.AdapterCompleted;
        try
        {
            if (!await connection.InitializeAsync(cancellationToken)) return;
            var attempts = 0;
            for (var requestCount = 0; requestCount < 64; requestCount++)
            {
                var request = await connection.ReadAsync(cancellationToken);
                if (request is null) return;
                var material = Authentication(request, profile);
                var response = Response(request, profile, material is not null);
                if (material is not null && response.Status == 401)
                {
                    await RecordAuthenticationAsync(eventSink, context, profile, material.Username, material.Method,
                        "HTTP_401", ++attempts, material.MaterialType, material.Content, cancellationToken);
                }
                var close = request.Close || attempts >= profile.MaxAuthenticationAttempts || requestCount == 63;
                await connection.WriteAsync(response, request.Method == "HEAD", close, cancellationToken);
                if (close) return;
            }
        }
        catch (AuthenticationRecordingException) { closeReason = SessionCloseReason.StorageDegraded; }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) { closeReason = SessionCloseReason.IdleTimeout; }
        catch (OperationCanceledException) { closeReason = SessionCloseReason.ListenerStopping; throw; }
        catch (AuthenticationException)
        {
            closeReason = SessionCloseReason.ProtocolViolation;
            await eventSink.AppendAsync(Event(context, "ProtocolViolation", "tls", "failure", "TLS negotiation failed"), cancellationToken);
        }
        catch (InvalidDataException)
        {
            closeReason = SessionCloseReason.ProtocolViolation;
            await eventSink.AppendAsync(Event(context, "ProtocolViolation", "http", "failure", "Invalid HTTP message"), cancellationToken);
            try { await connection.WriteAsync(new(400, "{\"error\":\"bad request\"}", []), false, true, cancellationToken); }
            catch (IOException) { }
        }
        catch (IOException) { closeReason = SessionCloseReason.ClientClosed; }
        catch (Exception) { closeReason = SessionCloseReason.InternalError; throw; }
        finally { await session.CloseAsync(closeReason, CancellationToken.None); }
    }

    protected static HttpAuthenticationMaterial? HeaderAuthentication(ProtocolHttpRequest request, bool basicIsToken = false)
    {
        if (!request.Headers.TryGetValue("Authorization", out var value)) return null;
        var split = value.IndexOf(' ');
        if (split <= 0) throw new InvalidDataException("Invalid authorization");
        var scheme = value[..split]; var material = value[(split + 1)..].Trim();
        if (scheme.Equals("Basic", StringComparison.OrdinalIgnoreCase))
        {
            string decoded;
            try { decoded = new UTF8Encoding(false, true).GetString(Convert.FromBase64String(material)); }
            catch (Exception ex) when (ex is FormatException or DecoderFallbackException) { throw new InvalidDataException("Invalid basic credentials"); }
            var colon = decoded.IndexOf(':');
            if (colon < 0) throw new InvalidDataException("Invalid basic credentials");
            var username = decoded[..colon]; var secret = decoded[(colon + 1)..];
            return basicIsToken
                ? new(username, "HTTP-Basic-Token", "Token", JsonSerializer.SerializeToUtf8Bytes(new { username, token = secret }))
                : new(username, "HTTP-Basic", "Plaintext", JsonSerializer.SerializeToUtf8Bytes(new { username, password = secret }));
        }
        if (scheme.Equals("Bearer", StringComparison.OrdinalIgnoreCase) || scheme.Equals("Token", StringComparison.OrdinalIgnoreCase))
            return new(null, $"HTTP-{scheme.ToLowerInvariant()}", "Token", JsonSerializer.SerializeToUtf8Bytes(new { token = material }));
        if (scheme.Equals("ApiKey", StringComparison.OrdinalIgnoreCase))
            return new(null, "HTTP-ApiKey", "ApiKey", JsonSerializer.SerializeToUtf8Bytes(new { apiKey = material }));
        return new(null, "HTTP-Unsupported", "Response", JsonSerializer.SerializeToUtf8Bytes(new { authorization = value }));
    }

    protected static IReadOnlyDictionary<string, string> QueryParameters(string target)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        var question = target.IndexOf('?');
        if (question < 0) return result;
        foreach (var pair in target[(question + 1)..].Split('&'))
        {
            var pieces = pair.Split('=', 2);
            var key = Uri.UnescapeDataString(pieces[0].Replace('+', ' '));
            var value = pieces.Length == 2 ? Uri.UnescapeDataString(pieces[1].Replace('+', ' ')) : "";
            if (!result.TryAdd(key, value)) throw new InvalidDataException("Duplicate query parameter");
        }
        return result;
    }
}
