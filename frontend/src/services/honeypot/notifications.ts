import { request } from '@umijs/max';
import type { ApiResult, PageResult } from './api';

export interface ReportScheduleSettings {
  kind: string; enabled: boolean; sendTime: string; recipients: string[];
  nextRunAtUtc?: string | null; lastRunAtUtc?: string | null; lastRunStatus?: string | null;
}
export interface NotificationSettings {
  enabled: boolean; host: string; port: number; useSsl: boolean; securityMode: string;
  fromEmail: string; fromName: string; username: string; hasCredential: boolean; timeoutSeconds: number;
  defaultRecipients: string[]; maxPerHour: number; maxPerRecipientPerHour: number;
  testCooldownSeconds: number; resendCooldownSeconds: number; schedules: ReportScheduleSettings[];
}
export const defaultNotificationSettings: NotificationSettings = {
  enabled: false, host: '', port: 465, useSsl: true, securityMode: 'SslOnConnect',
  fromEmail: '', fromName: '通研 Honeypot', username: '', hasCredential: false, timeoutSeconds: 15,
  defaultRecipients: [], maxPerHour: 100, maxPerRecipientPerHour: 20, testCooldownSeconds: 60, resendCooldownSeconds: 60,
  schedules: ['Daily', 'Weekly', 'Monthly'].map((kind) => ({ kind, enabled: false, sendTime: '08:00', recipients: [] })),
};
export interface NotificationTaskResult { deliveryIds: string[]; message: string }
export interface EmailDeliverySummary {
  id: string; kind: string; recipient: string; subject: string; status: string;
  createdAtUtc: string; sentAtUtc?: string | null; nextAttemptAtUtc?: string | null; attemptCount: number;
  lastErrorCode?: string | null; lastErrorMessage?: string | null; reportId?: string | null;
  periodStartAtUtc?: string | null; periodEndAtUtc?: string | null;
}
export interface EmailDeliveryDetails {
  delivery: EmailDeliverySummary; htmlBody: string; textBody: string; templateVersion: string; canRetry: boolean;
  attempts: { attemptNumber: number; startedAtUtc: string; completedAtUtc?: string | null; outcome: string; errorCode?: string | null; errorMessage?: string | null }[];
}
export interface EmailDeliveryQuery { page: number; pageSize: number; kind?: string; status?: string; recipient?: string; fromUtc?: string; toUtc?: string }
export const mailKindLabels: Record<string, string> = { Test: '测试邮件', Daily: '日报', Weekly: '周报', Monthly: '月报', Manual: '手动报告', Custom: '自定义报告' };
export const mailStatusLabels: Record<string, string> = { Pending: '排队中', Sending: '发送中', Accepted: 'SMTP 已受理', Failed: '发送失败', Retrying: '等待重试', Unknown: '发送结果未知' };

export function getNotificationSettings(signal?: AbortSignal) { return request<ApiResult<NotificationSettings>>('/api/v1/settings/notifications', { method: 'GET', signal, skipErrorHandler: true }); }
export function saveNotificationSettings(settings: NotificationSettings, authorizationCode?: string) { return request<ApiResult<NotificationSettings>>('/api/v1/settings/notifications', { method: 'PUT', data: { settings, authorizationCode: authorizationCode || undefined }, skipErrorHandler: true }); }
export function sendTestEmail(recipient: string) { return request<ApiResult<NotificationTaskResult>>('/api/v1/notifications/test', { method: 'POST', data: { recipient }, skipErrorHandler: true }); }
export function getEmailDeliveries(query: EmailDeliveryQuery, signal?: AbortSignal) { return request<ApiResult<PageResult<EmailDeliverySummary>>>('/api/v1/notifications/emails', { method: 'GET', params: query, signal, skipErrorHandler: true }); }
export function getEmailDelivery(id: string, signal?: AbortSignal) { return request<ApiResult<EmailDeliveryDetails>>(`/api/v1/notifications/emails/${encodeURIComponent(id)}`, { method: 'GET', signal, skipErrorHandler: true }); }
export function retryEmailDelivery(id: string) { return request<ApiResult<NotificationTaskResult>>(`/api/v1/notifications/emails/${encodeURIComponent(id)}/retry`, { method: 'POST', skipErrorHandler: true }); }
