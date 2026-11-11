import { request } from '@umijs/max';
import type { ApiResult } from './api';

export type SyslogProtocol = 'Udp' | 'Tcp' | 'Tls' | 'Relp';
export interface SyslogTarget { id: string; name: string; host: string; port: number; protocol: SyslogProtocol; enabled: boolean; ignoreSslErrors: boolean }
export interface SyslogSettings { enabled: boolean; targets: SyslogTarget[]; connectTimeoutSeconds: number; writeTimeoutSeconds: number; queueCapacity: number; spoolMaxBytes: number; retentionHours: number }
export interface SyslogSettingsSnapshot { settings: SyslogSettings; revision: number; hostname: string; configFault?: string | null }
export interface SyslogTargetStatus { targetId: string; state: string; pendingCount: number; sentCount: number; confirmedCount: number; failedCount: number; retriedCount: number; droppedCount: number; truncatedCount: number; lastSentAtUtc?: string | null; lastConfirmedAtUtc?: string | null; lastErrorCode?: string | null }
export interface SyslogDeliveryStatus { enabled: boolean; hostname: string; targets: SyslogTargetStatus[]; configFault?: string | null; pausedPendingCount?: number; discardedPausedCount?: number }
export interface SyslogTestResult { targetId: string; correlationId: string; succeeded: boolean; stage: string; errorCode?: string | null; completedAtUtc?: string | null }
export const defaultSyslogSettings: SyslogSettings = { enabled: false, targets: [], connectTimeoutSeconds: 10, writeTimeoutSeconds: 10, queueCapacity: 10000, spoolMaxBytes: 268435456, retentionHours: 24 };
export const syslogProtocolPorts: Record<SyslogProtocol, number> = { Udp: 514, Tcp: 514, Tls: 6514, Relp: 2514 };
export const syslogTestMessageLimit = 256;
export function getSyslogSettings(signal?: AbortSignal) { return request<ApiResult<SyslogSettingsSnapshot>>('/api/v1/settings/syslog', { signal, skipErrorHandler: true }); }
export function saveSyslogSettings(settings: SyslogSettings, expectedRevision: number) { return request<ApiResult<SyslogSettingsSnapshot>>('/api/v1/settings/syslog', { method: 'PUT', data: { settings, expectedRevision }, skipErrorHandler: true }); }
export function getSyslogStatus(signal?: AbortSignal) { return request<ApiResult<SyslogDeliveryStatus>>('/api/v1/syslog/status', { signal, skipErrorHandler: true }); }
export function testSyslogTarget(targetId: string, message?: string) { return request<ApiResult<SyslogTestResult>>('/api/v1/syslog/test', { method: 'POST', data: { targetId, message }, skipErrorHandler: true }); }
