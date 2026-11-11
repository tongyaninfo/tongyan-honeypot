import { getAccessToken } from './identity';

export type FrontendDiagnosticCode = 'UI_UNHANDLED_ERROR' | 'UI_EXPORT_FAILED' | 'UI_REQUEST_FAILED' | 'UI_REALTIME_INTERRUPTED' | 'UI_REALTIME_RECOVERED' | 'UI_NETWORK_RECOVERED';
const routes = new Set(['overview', 'services', 'events', 'threats', 'credentials', 'reports', 'system']);
const recent = new Map<string, number>();
let inFlight = 0;
let windowStarted = 0;
let windowCount = 0;

/** 固定页面键不包含动态路径、查询参数和 hash，避免会话凭据进入诊断正文。 */
export function diagnosticRouteKey(pathname = typeof window === 'undefined' ? '' : window.location.pathname) {
  const key = pathname.split('/')[1] ?? '';
  return routes.has(key) ? key : 'unknown';
}

/** 仅发送事件码和安全数字；绕过请求拦截器，失败不重试、不再报告，避免递归。 */
export function reportFrontendDiagnostic(eventCode: FrontendDiagnosticCode, httpStatus?: number): void {
  if (typeof window === 'undefined' || typeof fetch === 'undefined' || navigator.onLine === false || inFlight >= 2) return;
  let token: string | undefined;
  try { token = getAccessToken(); } catch { return; }
  if (!token) return;
  const now = Date.now();
  if (now - windowStarted >= 60000) { windowStarted = now; windowCount = 0; }
  if (windowCount >= 30) return;
  const routeKey = diagnosticRouteKey();
  const key = `${eventCode}:${routeKey}`;
  if (recent.has(key) && now - (recent.get(key) ?? 0) < 10000) return;
  if (recent.size >= 64) recent.clear();
  recent.set(key, now); windowCount++; inFlight++;
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), 5000);
  const base = process.env.HONEYPOT_API_BASE_URL?.replace(/\/$/, '') ?? '';
  const body = { eventCode, routeKey, count: 1, ...(Number.isInteger(httpStatus) && httpStatus! >= 400 && httpStatus! <= 599 ? { httpStatus } : {}) };
  try {
    void fetch(`${base}/api/v1/telemetry/frontend-logs`, { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify(body), signal: controller.signal, credentials: 'omit', cache: 'no-store' })
      .catch(() => undefined).finally(() => { inFlight--; window.clearTimeout(timeout); });
  } catch { inFlight--; window.clearTimeout(timeout); }
}

/** 不读取 Error/Promise rejection 的正文或堆栈，只记录发生了未处理异常。 */
export function installFrontendDiagnostics() {
  const failed = () => reportFrontendDiagnostic('UI_UNHANDLED_ERROR');
  const online = () => reportFrontendDiagnostic('UI_NETWORK_RECOVERED');
  window.addEventListener('error', failed);
  window.addEventListener('unhandledrejection', failed);
  window.addEventListener('online', online);
  return () => {
    window.removeEventListener('error', failed);
    window.removeEventListener('unhandledrejection', failed);
    window.removeEventListener('online', online);
  };
}
