using Honeypot.Api.Models;
using MailKit.Net.Smtp;
using MailKit.Security;
using MimeKit;

namespace Honeypot.Api.Service.impl;

/// <summary>SMTP 返回受理后才标记成功；提交阶段断线无法断言未投递，禁止自动重发。</summary>
public sealed class MailKitTransport : IMailTransport
{
    public async Task<MailTransportResult> SendAsync(NotificationTransportSettings settings,
        MailTransportMessage message, CancellationToken cancellationToken = default)
    {
        var submitting = false;
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(settings.TimeoutSeconds));
        var sendToken = deadline.Token;
        try
        {
            using var client = new SmtpClient { Timeout = settings.TimeoutSeconds * 1000 };
            var security = settings.SecurityMode switch
            {
                "SslOnConnect" => SecureSocketOptions.SslOnConnect,
                "StartTls" => SecureSocketOptions.StartTls,
                "None" => SecureSocketOptions.None,
                _ => throw new ArgumentException("不支持的 SMTP 加密模式。")
            };
            // 不使用 Auto/StartTlsWhenAvailable，避免勾选加密后悄悄降级明文。
            await client.ConnectAsync(settings.Host, settings.Port, security, sendToken);
            await client.AuthenticateAsync(settings.Username, settings.Credential, sendToken);
            var mime = new MimeMessage { Subject = message.Subject, MessageId = message.MessageId };
            mime.From.Add(new MailboxAddress(settings.SenderName, settings.SenderAddress));
            mime.To.Add(MailboxAddress.Parse(message.Recipient));
            mime.Body = new BodyBuilder { HtmlBody = message.HtmlBody, TextBody = message.TextBody }.ToMessageBody();
            submitting = true;
            await client.SendAsync(mime, sendToken);
            // Dispose 的断连不影响服务端已确认的 DATA 受理结果。
            return MailTransportResult.Accepted;
        }
        catch (MailKit.Security.AuthenticationException)
        {
            return new("Failed", "SMTP_AUTH_FAILED", "邮件服务器认证失败，请检查账号及授权码。");
        }
        catch (SslHandshakeException)
        {
            return new("Failed", "SMTP_TLS_FAILED", "邮件服务器 TLS 握手失败，请检查加密模式和证书。");
        }
        catch (SmtpCommandException error)
        {
            var temporary = (int)error.StatusCode is >= 400 and < 500;
            return new(temporary ? "Retrying" : "Failed", temporary ? "SMTP_TEMPORARY_REJECTION" : "SMTP_REJECTED",
                temporary ? "邮件服务器暂时拒绝本次投递，将有限重试。" : "邮件服务器拒绝本次投递，请检查地址和服务策略。");
        }
        catch (Exception error) when (error is IOException or System.Net.Sockets.SocketException or
            SmtpProtocolException or OperationCanceledException or TimeoutException)
        {
            return submitting
                ? new("Unknown", "SMTP_RESULT_UNKNOWN", "邮件提交阶段连接中断，可能已被服务器受理，请核实后再决定重发。")
                : new("Retrying", "SMTP_CONNECTION_FAILED", "无法连接邮件服务器，将有限重试。");
        }
        catch (Exception error) when (error is ArgumentException or FormatException or NotSupportedException or InvalidOperationException)
        {
            return new("Failed", "SMTP_CONFIGURATION_INVALID", "邮件服务器配置或邮件格式无效。");
        }
    }
}
