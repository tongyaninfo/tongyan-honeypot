import { request } from '@umijs/max';
import type { ApiResult, PageResult } from './api';

const path = '/api/v1/mcp';
const options = { skipErrorHandler: true };

export type McpAccess = 'ReadOnly' | 'ReadWrite';
export type McpKeyStatus = 'Active' | 'Expired' | 'Revoked';
export type McpCallResult = 'Pending' | 'Success' | 'ToolError' | 'ProtocolError' | 'Denied' | 'RateLimited' | 'Unavailable' | 'Unknown';

export interface McpSettings {
  enabled: boolean;
  auditRetentionDays: number;
  auditAvailable: boolean;
  auditDroppedCount?: number;
  updatedAtUtc?: string | null;
}

export interface McpToolPermission {
  id: string;
  label: string;
  description: string;
  access: McpAccess;
  requiresInstanceScope?: boolean;
}

export interface McpPermissions {
  groups: { id: string; label: string; tools: McpToolPermission[] }[];
  instances: { id: string; name: string; adapterKey?: string }[];
}

export interface CreateMcpKeyRequest {
  name: string;
  access: McpAccess;
  permissionIds: string[];
  instanceIds: string[];
  expiresAtUtc?: string;
}

export interface McpKey extends Omit<CreateMcpKeyRequest, 'expiresAtUtc'> {
  id: string;
  prefix: string;
  createdAtUtc: string;
  expiresAtUtc?: string | null;
  revokedAtUtc?: string | null;
  lastUsedAtUtc?: string | null;
  status: McpKeyStatus;
}

export interface McpKeyCreated {
  key: McpKey;
  secret: string;
}

export interface McpPageQuery {
  page: number;
  pageSize: number;
}

export interface McpAuditQuery extends McpPageQuery {
  keyId?: string;
  tool?: string;
  sourceIp?: string;
  result?: McpCallResult;
  fromUtc?: string;
  toUtc?: string;
}

export interface McpAuditSummary {
  id: string;
  occurredAtUtc: string;
  keyId?: string | null;
  keyName?: string | null;
  keyPrefix?: string | null;
  sourceIp?: string | null;
  tool?: string | null;
  httpMethod?: string | null;
  mcpMethod?: string | null;
  httpStatus?: number | null;
  result: McpCallResult;
  durationMs?: number | null;
}

export interface McpAuditDetails extends McpAuditSummary {
  path?: string | null;
  client?: string | null;
  protocolVersion?: string | null;
  requestId?: string | null;
  traceId?: string | null;
  errorCode?: string | null;
  errorMessage?: string | null;
  requestBytes?: number | null;
  responseBytes?: number | null;
  requestHeaders?: string | null;
  requestParams?: string | null;
  responseHeaders?: string | null;
  responseBody?: string | null;
  requestBodyOmittedReason?: string | null;
  responseBodyOmittedReason?: string | null;
  captureNote?: string | null;
}

export const getMcpSettings = (signal?: AbortSignal) =>
  request<ApiResult<McpSettings>>(`${path}/settings`, { ...options, method: 'GET', signal });

export const updateMcpSettings = (data: Partial<Pick<McpSettings, 'enabled' | 'auditRetentionDays'>>) =>
  request<ApiResult<McpSettings>>(`${path}/settings`, { ...options, method: 'PUT', data });

export const getMcpPermissions = (signal?: AbortSignal) =>
  request<ApiResult<McpPermissions>>(`${path}/permissions`, { ...options, method: 'GET', signal });

export const getMcpKeys = (params: McpPageQuery, signal?: AbortSignal) =>
  request<ApiResult<PageResult<McpKey>>>(`${path}/keys`, { ...options, method: 'GET', params, signal });

export const createMcpKey = (data: CreateMcpKeyRequest) =>
  request<ApiResult<McpKeyCreated>>(`${path}/keys`, { ...options, method: 'POST', data });

export const revokeMcpKey = (id: string) =>
  request<ApiResult<unknown>>(`${path}/keys/${encodeURIComponent(id)}/revoke`, { ...options, method: 'POST' });

export const deleteMcpKey = (id: string) =>
  request<ApiResult<unknown>>(`${path}/keys/${encodeURIComponent(id)}`, { ...options, method: 'DELETE' });

export const getMcpAudits = (params: McpAuditQuery, signal?: AbortSignal) =>
  request<ApiResult<PageResult<McpAuditSummary>>>(`${path}/audits`, { ...options, method: 'GET', params, signal });

export const getMcpAudit = (id: string, signal?: AbortSignal) =>
  request<ApiResult<McpAuditDetails>>(`${path}/audits/${encodeURIComponent(id)}`, { ...options, method: 'GET', signal });
