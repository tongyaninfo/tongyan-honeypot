import { request } from '@umijs/max';
import type { ApiResult, PageResult } from './api';
import type { NotificationTaskResult } from './notifications';

export type ReportPeriodKind = 'day' | 'week' | 'month' | 'custom';
export interface ReportQuery { period: ReportPeriodKind; startAtUtc?: string; endAtUtc?: string }
export interface ReportTotals {
  eventCount: number | null; acceptedConnections: number | null; uniqueSourceIps: number | null;
  newSourceIps: number | null; authenticationAttempts: number | null; authenticationFailures: number | null;
  protocolViolations: number | null; evidenceCount: number | null; truncatedEvents: number | null; sessionClosed: number | null;
}
export interface ReportBreakdown { key: string; events: number; connections: number; authenticationFailures: number; sourceIps: number }
export interface OperationReport {
  generatedAtUtc: string;
  period: { kind: string; timeZone: string; startAtUtc: string; endAtUtc: string; granularity: string; isCurrentPeriod: boolean };
  coverage: { status: string; coveredSeconds: number; unknownSeconds: number; coveragePercent: number; firstSampleAtUtc?: string | null; lastSampleAtUtc?: string | null; persistenceFailures: number; hasObservedEvents: boolean };
  totals: ReportTotals;
  comparison: { startAtUtc: string; endAtUtc: string; coverageStatus: string; totals: ReportTotals; connectionChangePercent: number | null; sourceIpChangePercent: number | null; authenticationFailureChangePercent: number | null };
  trend: { startAtUtc: string; events: number | null; connections: number | null; authenticationFailures: number | null; protocolViolations: number | null; coverageStatus: string }[];
  protocols: ReportBreakdown[]; ports: ReportBreakdown[]; sources: ReportBreakdown[]; regions: ReportBreakdown[];
  usernames: ReportBreakdown[]; authenticationMethods: ReportBreakdown[]; riskSignals: ReportBreakdown[]; evidence: ReportBreakdown[];
  runtime: { sampleCount: number; averageProcessCpuPercent: number | null; peakProcessCpuPercent: number | null; averageProcessMemoryBytes: number | null; peakProcessMemoryBytes: number | null; peakActiveConnections: number | null; averageRunningListeners: number | null; peakFailedListeners: number | null; lastConfiguredListeners: number | null; allListenersRunningPercent: number | null; lastDataDiskFreeBytes: number | null; minimumDataDiskFreeBytes: number | null; lastSampleAtUtc?: string | null };
  mailSummary?: { accepted: number; failed: number; pending: number; retrying: number; unknown: number; sending: number } | null;
  notes: string[];
}

export function getOperationReport(query: ReportQuery, signal?: AbortSignal) {
  return request<ApiResult<OperationReport>>('/api/v1/reports', { method: 'GET', params: query, signal, skipErrorHandler: true });
}

export function sendOperationReport(data: ReportQuery & { recipients: string[] }) {
  return request<ApiResult<NotificationTaskResult>>('/api/v1/reports/send', { method: 'POST', data, skipErrorHandler: true });
}

export interface ReportHistoryItem { id: string; kind: string; title: string; startAtUtc: string; endAtUtc: string; generatedAtUtc: string; recipientCount: number }
export function getReportHistory(page: number, pageSize: number, signal?: AbortSignal) { return request<ApiResult<PageResult<ReportHistoryItem>>>('/api/v1/reports/history', { method: 'GET', params: { page, pageSize }, signal, skipErrorHandler: true }); }
export function getReportHistoryDetails(id: string, signal?: AbortSignal) { return request<ApiResult<OperationReport>>(`/api/v1/reports/history/${encodeURIComponent(id)}`, { method: 'GET', signal, skipErrorHandler: true }); }
