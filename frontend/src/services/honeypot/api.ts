import { request } from '@umijs/max';

export interface ApiResult<T> {
  success: boolean;
  code: string;
  message: string;
  data: T;
}

export interface IPLocationSettings {
  enabled: boolean;
  protocol: 'http' | 'https';
  host: string;
  port: number;
  database: 'CZ88' | 'ip2location' | 'ip2region' | 'dbip' | 'ipinfo' | 'geolite2';
  timeoutSeconds: number;
}

export interface IPLocationResult {
  ip: string;
  status: 'disabled' | 'pending' | 'resolved' | 'private' | 'reserved' | 'network' | 'failed' | 'invalid' | 'busy';
  displayName?: string | null;
  country?: string | null;
  province?: string | null;
  city?: string | null;
  district?: string | null;
  isp?: string | null;
}

export interface IPLocationBatch {
  enabled: boolean;
  items: IPLocationResult[];
}

/** 与后端批量接口保持一致，避免单个超长输入导致整批查询被拒绝。 */
export const maxIPLocationInputLength = 80;

export const defaultIPLocationSettings: IPLocationSettings = {
  enabled: false, protocol: 'https', host: 'ip.tongyaninfo.com', port: 443,
  database: 'CZ88', timeoutSeconds: 2,
};

export function getIPLocationSettings(options?: Record<string, unknown>) {
  return request<ApiResult<IPLocationSettings>>('/api/v1/settings/ip-location', {
    method: 'GET', skipErrorHandler: true, ...options,
  });
}

export function saveIPLocationSettings(data: IPLocationSettings) {
  return request<ApiResult<IPLocationSettings>>('/api/v1/settings/ip-location', {
    method: 'PUT', data, skipErrorHandler: true,
  });
}

/** 只提交查询任务和读取缓存，外部解析由服务器后台执行。 */
export function resolveIPLocations(ips: string[], signal?: AbortSignal) {
  return request<ApiResult<IPLocationBatch>>('/api/v1/ip-locations/resolve', {
    method: 'POST', data: { ips }, signal, timeout: 5000, skipErrorHandler: true,
  });
}

export interface PageResult<T> {
  items: T[];
  total: number;
  page: number;
  pageSize: number;
}

export interface HealthStatus {
  service: string;
  version: string;
  utcTime: string;
}

export interface MetricBucket {
  key: string;
  count: number;
}

export interface AdapterActivity {
  adapterKey: string;
  acceptedConnections: number;
  authenticationFailures: number;
  sourceIpCount: number;
  protocolViolations: number;
  lastActivityAtUtc: string;
}

export interface ActivityHour {
  key: string;
  acceptedConnections: number | null;
  authenticationFailures: number | null;
  coverageStatus?: 'complete' | 'partial' | 'unknown';
}

export interface ListenerOverview {
  listenerId: string;
  instanceId: string;
  adapterKey: string;
  port: number;
  state: string;
  activeConnections: number;
  acceptedCount: number;
  errorCount: number;
}

export interface OverviewMetrics {
  generatedAtUtc: string;
  eventCount: number;
  acceptedConnections: number;
  authenticationAttempts: number;
  authenticationFailures: number;
  todayAuthenticationFailures?: number;
  protocolViolations: number;
  sessionClosed: number;
  threatIpCount: number;
  serviceInstanceCount: number;
  listenerCount: number;
  runningListenerCount: number;
  failedListenerCount: number;
  activeConnections: number;
  acceptedCount: number;
  listenerErrorCount: number;
  eventsByAdapter: MetricBucket[];
  eventsByOutcome: MetricBucket[];
  eventsByHour: MetricBucket[];
  adapterActivity?: AdapterActivity[];
  activityByHour?: ActivityHour[];
  listeners: ListenerOverview[];
  eventStorage?: {
    queueDepth: number;
    rejectedEvents: number;
    databaseBytes: number;
    diskBudgetBlocked: boolean;
    retentionAvailable: boolean;
    lastPersistedAtUtc?: string | null;
  };
  host?: {
    osVersion: string;
    hostName: string;
    ipAddresses: string[];
    bootTimeUtc?: string | null;
  };
}

export type OverviewConnectionScope =
  | 'active'
  | 'accepted'
  | 'authenticationFailures'
  | 'threatConnections';

export type OverviewAdapterActivityMetric =
  | 'acceptedConnections'
  | 'authenticationFailures'
  | 'sourceIpCount'
  | 'protocolViolations';

export interface OverviewAdapterActivityFilter {
  scope: 'adapterActivity';
  adapterKey: string;
  metric: OverviewAdapterActivityMetric;
}

export type OverviewConnectionFilter =
  | { scope: OverviewConnectionScope }
  | OverviewAdapterActivityFilter;

export interface OverviewConnectionRow {
  id: string;
  connectionId: string;
  occurredAtUtc: string;
  sourceIp: string;
  sourcePort?: number | null;
  adapterKey: string;
  destinationPort: number;
  username?: string | null;
  credentialArtifactId?: string | null;
  materialType?: string | null;
  eventType?: string | null;
  protocolViolationSummary?: string | null;
}

export interface ConnectionMapEvent {
  id: string;
  occurredAtUtc: string;
  adapterKey: string;
  longitude: number;
  latitude: number;
  locationLabel: string;
  sourceIp?: string;
  country?: string;
}

export interface ConnectionMapOrigin {
  id: string;
  longitude: number;
  latitude: number;
  locationLabel: string;
  adapterKey: string;
  connectionCount: number;
  sourceIpCount: number;
  sources: { ip: string; country: string }[];
}

export type ConnectionMapWindowSeconds = 60 | 600 | 7200 | 86400;

export interface ConnectionMapSnapshot {
  sampledAtUtc: string;
  windowSeconds: number;
  target: {
    status: 'ready' | 'pending' | 'unavailable' | 'disabled';
    label?: string;
    latitude?: number | null;
    longitude?: number | null;
    source?: string;
    stale?: boolean;
    updatedAtUtc?: string | null;
  };
  events: ConnectionMapEvent[];
  origins?: ConnectionMapOrigin[];
  adapterKeys?: string[];
  coverage: {
    observed: number;
    mapped: number;
    unknown: number;
    private: number;
    pending: number;
    deferred?: number;
    omitted: number;
  };
  locationEnabled: boolean;
}

export interface ServiceType {
  category?: string;
  systemGroup?: string;
  defaultInstanceName?: string;
  defaultPort?: number;
  defaultHostName?: string;
  defaultProduct?: string;
  defaultProductVersion?: string;
  adapterKey: string;
  displayName: string;
  transport: string[];
  adapterVersion: string;
  supportedFidelityLevels: string[];
  capabilities: string[];
}

export interface ListenerBinding {
  listenerId: string;
  bindAddress: string;
  port: number;
  transport: string;
  enabled: boolean;
  state?: string;
  activeConnections?: number;
}

export interface ServiceInstance {
  instanceId: string;
  displayName?: string;
  adapterKey: string;
  adapterVersion?: string;
  profile: {
    profileId: string;
    adapterKey: string;
    advertisedProduct?: string;
    advertisedVersion?: string;
    advertisedHostName?: string;
    postgreSqlAuthenticationMethod?: 'scram-sha-256' | 'password' | 'md5';
    oracleServiceName?: string;
    influxDbApiVersion?: 'v1' | 'v2';
    fidelityLevel?: string;
    authMode?: string;
    recordPassword?: boolean;
    storeCredentialEvidence?: boolean;
  };
  desiredState?: string;
  currentState?: string;
  autoStart?: boolean;
  lastError?: string;
  bindings: ListenerBinding[];
  updatedAtUtc?: string;
}

export interface RuntimeListener extends ListenerBinding {
  /** 当前运行时接口返回 instanceId；兼容旧版 serviceInstanceId 字段。 */
  instanceId?: string;
  serviceInstanceId?: string;
  adapterKey?: string;
  profileId?: string;
  acceptedCount?: number;
  rejectedCount?: number;
  errorCount?: number;
}

export interface InteractionEvent {
  eventId: string;
  connectionId: string;
  sequence: number;
  eventType: string;
  occurredAtUtc: string;
  sourceIp: string;
  sourcePort?: number;
  destinationPort: number;
  destinationIp?: string;
  adapterKey: string;
  serviceInstanceId: string;
  listenerId: string;
  stage?: string;
  /** 协议适配器生成的固定诊断码。历史事件可能没有此字段。 */
  protocolErrorCode?: string | null;
  outcome?: string;
  payloadSummary?: string;
  username?: string;
  domain?: string;
  database?: string;
  authenticationMethod?: string;
  authenticationFailureCode?: string;
  authenticationAttempt?: number;
  materialType?: string;
  credentialCaptureStatus?: string;
  riskDelta?: number;
  credentialArtifactId?: string;
  /** 行为列表关联的原始步骤数；原始事件列表不返回此字段。 */
  eventCount?: number;
}

export interface ThreatIpProfile {
  threatId: string;
  sourceIp: string;
  firstSeenUtc: string;
  lastSeenUtc: string;
  currentScore: number;
  maxScore: number;
  scoreVersion: string;
  status: string;
  attemptCount: number;
  sessionCount: number;
  activeSessionCount: number;
  authenticationAttemptCount: number;
  protocolViolationCount: number;
  servicesTouched: string[];
  portsTouched: number[];
  lastEventId?: string;
  lastReason?: string;
  expiresAtUtc?: string;
}

export interface CredentialEvidenceSummary {
  credentialArtifactId: string;
  connectionId: string;
  eventId: string;
  sourceIp: string;
  adapterKey: string;
  materialType: 'Plaintext' | 'Response' | 'Ciphertext' | 'Decrypted' | string;
  capturedAtUtc: string;
  retentionUntilUtc?: string;
  truncated?: boolean;
}

export interface CredentialEvidenceView {
  summary: CredentialEvidenceSummary;
  content: string;
}

export interface PasswordBookRow {
  username: string;
  adapterKey: string;
  authenticationCount: number;
  lastUsedAtUtc: string;
  credentialArtifactId: string;
}

export interface CredentialEvidenceExportItem {
  artifactId: string;
  outcome: string;
  evidence?: CredentialEvidenceView;
}

export function normalizePage<T>(data: PageResult<T> | T[] | undefined): PageResult<T> {
  if (Array.isArray(data)) {
    return { items: data, total: data.length, page: 1, pageSize: data.length };
  }
  return data ?? { items: [], total: 0, page: 1, pageSize: 20 };
}

export interface PageQuery {
  page?: number;
  pageSize?: number;
}

export interface EventQuery extends PageQuery {
  sourceIp?: string;
  eventType?: string;
  adapterKey?: string;
  view?: 'activity' | 'raw';
  connectionIds?: string;
}

/** 导出逐页读取同一筛选结果，按 ID 合并实时新增导致跨页重复的记录。 */
export async function loadExportRows<T>(
  fetchPage: (query: PageQuery) => Promise<ApiResult<PageResult<T>>>,
  key: (row: T) => string,
  snapshot?: PageResult<T>,
) {
  const read = async (page: number) => {
    const response = await fetchPage({ page, pageSize: 100 });
    if (!response.success || !response.data) throw new Error('Export data unavailable');
    return response.data;
  };
  if (snapshot?.page === 1 && snapshot.items.length >= snapshot.total) return snapshot.items;
  const first = await read(1);
  const items = new Map(first.items.map((row) => [key(row), row]));
  const pages = Math.ceil(first.total / Math.max(first.pageSize, 1));
  for (let page = 2; page <= pages; page++) {
    const next = await read(page);
    for (const row of next.items) items.set(key(row), row);
    if (!next.items.length) break;
  }
  return [...items.values()];
}

function pageParams(params?: object) {
  return Object.fromEntries(
    Object.entries((params as Record<string, unknown>) ?? {}).filter(([, value]) => value !== undefined && value !== ''),
  );
}

export async function getHealth(options?: Record<string, unknown>) {
  return request<ApiResult<HealthStatus>>('/health', {
    method: 'GET',
    ...(options || {}),
  });
}

export async function getOverviewMetrics(options?: Record<string, unknown>) {
  return request<ApiResult<OverviewMetrics>>('/api/v1/metrics/overview', {
    method: 'GET',
    ...(options || {}),
  });
}

export async function getOverviewConnections(
  query: PageQuery & OverviewConnectionFilter,
) {
  return request<ApiResult<PageResult<OverviewConnectionRow>>>(
    '/api/v1/metrics/overview/connections',
    { method: 'GET', params: pageParams(query), skipErrorHandler: true },
  );
}

export function getOverviewConnectionMap(windowSeconds: ConnectionMapWindowSeconds, signal?: AbortSignal) {
  return request<ApiResult<ConnectionMapSnapshot>>('/api/v1/metrics/overview/connection-map', {
    method: 'GET', params: { windowSeconds }, signal, timeout: 5000, skipErrorHandler: true,
  });
}

export async function getServiceTypes(options?: Record<string, unknown>) {
  return request<ApiResult<ServiceType[] | PageResult<ServiceType>>>('/api/v1/service-types', {
    method: 'GET',
    ...(options || {}),
  });
}

export async function getServiceInstances(options?: Record<string, unknown>) {
  return request<ApiResult<ServiceInstance[] | PageResult<ServiceInstance>>>('/api/v1/service-instances', {
    method: 'GET',
    ...(options || {}),
  });
}

export async function createServiceInstance(
  data: ServiceInstance,
  options?: Record<string, unknown>,
) {
  return request<ApiResult<ServiceInstance>>('/api/v1/service-instances', {
    method: 'POST',
    data,
    ...(options || {}),
  });
}

export function setServiceInstanceRestartPolicy(instanceId: string, autoStart: boolean) {
  return request<ApiResult<ServiceInstance>>(
    `/api/v1/service-instances/${encodeURIComponent(instanceId)}/restart-policy`,
    { method: 'POST', data: { autoStart } },
  );
}

export async function startServiceInstance(instanceId: string, options?: Record<string, unknown>) {
  return request<ApiResult<unknown>>(`/api/v1/service-instances/${instanceId}/start`, {
    method: 'POST',
    ...(options || {}),
  });
}

export async function stopServiceInstance(instanceId: string, options?: Record<string, unknown>) {
  return request<ApiResult<unknown>>(`/api/v1/service-instances/${instanceId}/stop`, {
    method: 'POST',
    ...(options || {}),
  });
}

export async function getListeners(options?: Record<string, unknown>) {
  return request<ApiResult<PageResult<RuntimeListener>>>('/api/v1/listeners', {
    method: 'GET',
    ...(options || {}),
  });
}

export async function getEvents(query?: EventQuery, options?: Record<string, unknown>) {
  return request<ApiResult<PageResult<InteractionEvent>>>('/api/v1/events', {
    method: 'GET',
    params: pageParams(query),
    ...(options || {}),
  });
}

export async function getConnectionEvents(connectionId: string, options?: Record<string, unknown>) {
  return request<ApiResult<PageResult<InteractionEvent> | InteractionEvent[]>>(
    `/api/v1/connections/${encodeURIComponent(connectionId)}/events`,
    { method: 'GET', ...(options || {}) },
  );
}

/** 管理员证据原文独立读取，不能混入普通列表请求或持久化缓存。 */
export async function getCredentialEvidence(artifactId: string, options?: Record<string, unknown>) {
  return request<ApiResult<CredentialEvidenceView>>(
    `/api/v1/credential-evidence/${encodeURIComponent(artifactId)}`,
    { method: 'GET', headers: { 'Cache-Control': 'no-store' }, skipErrorHandler: true, ...(options || {}) },
  );
}

export async function getPasswordBook(query: PageQuery & { keyword?: string }, signal?: AbortSignal) {
  return request<ApiResult<PageResult<PasswordBookRow>>>('/api/v1/password-book', {
    method: 'GET', params: pageParams(query), signal, skipErrorHandler: true,
  });
}

export const evidenceExportBatchSize = 8;

/** 由服务端为每批检查角色和留存期限，并审计原文导出。 */
export async function exportCredentialEvidence(artifactIds: string[], signal?: AbortSignal) {
  return request<ApiResult<{ items: CredentialEvidenceExportItem[] }>>('/api/v1/credential-evidence/export', {
    method: 'POST', data: { artifactIds }, signal, skipErrorHandler: true,
  });
}

export async function getThreats(query?: PageQuery & { sort?: 'risk' }) {
  return request<ApiResult<PageResult<ThreatIpProfile>>>('/api/v1/threats', {
    method: 'GET',
    params: pageParams(query),
  });
}

export async function getCredentialEvidenceSummaries(query?: PageQuery) {
  return request<ApiResult<PageResult<CredentialEvidenceSummary>>>(
    '/api/v1/credential-evidence',
    {
      method: 'GET',
      params: pageParams({ ...query, summary: true }),
    },
  );
}
