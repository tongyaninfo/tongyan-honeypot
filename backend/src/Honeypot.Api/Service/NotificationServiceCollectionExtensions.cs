using Honeypot.Api.Service.impl;
using Honeypot.Api.Workers;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Honeypot.Api.Service;

public static class NotificationServiceCollectionExtensions
{
    public static IServiceCollection AddHoneypotNotifications(this IServiceCollection services)
    {
        services.TryAddSingleton(TimeProvider.System);
        services.AddSingleton<INotificationSettingsStore, FileNotificationSettingsStore>();
        services.AddSingleton<IMailTransport, MailKitTransport>();
        services.AddSingleton<IEmailTemplateRenderer, EmailTemplateRenderer>();
        services.AddSingleton<INotificationMailService, NotificationMailService>();
        services.AddHostedService<NotificationDeliveryWorker>();
        services.AddHostedService<ReportScheduleWorker>();
        return services;
    }
}
