import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { getAccessToken } from './identity';

vi.mock('./identity', () => ({ getAccessToken: vi.fn() }));
beforeEach(() => { vi.resetModules(); vi.clearAllMocks(); vi.mocked(getAccessToken).mockReturnValue('synthetic-session'); window.history.replaceState(null, '', '/credentials?token=synthetic-secret#sensitive'); });
afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); });

it('only sends fixed fields and strips dynamic URLs, messages and stacks', async () => {
  const fetcher = vi.fn().mockResolvedValue({ ok: true }); vi.stubGlobal('fetch', fetcher);
  const { reportFrontendDiagnostic, diagnosticRouteKey } = await import('./frontendDiagnostics');
  reportFrontendDiagnostic('UI_UNHANDLED_ERROR');
  expect(fetcher).toHaveBeenCalledOnce();
  const body = JSON.parse(fetcher.mock.calls[0][1].body);
  expect(body).toEqual({ eventCode: 'UI_UNHANDLED_ERROR', routeKey: 'credentials', count: 1 });
  expect(JSON.stringify(body)).not.toContain('synthetic-secret');
  expect(diagnosticRouteKey('/untrusted-user-value')).toBe('unknown');
  await Promise.resolve();
});

it('does not send before authentication and deduplicates failures without recursion', async () => {
  const fetcher = vi.fn().mockRejectedValue(new Error('synthetic-error-must-not-be-sent')); vi.stubGlobal('fetch', fetcher);
  const { reportFrontendDiagnostic } = await import('./frontendDiagnostics');
  vi.mocked(getAccessToken).mockReturnValue(undefined);
  reportFrontendDiagnostic('UI_EXPORT_FAILED'); expect(fetcher).not.toHaveBeenCalled();
  vi.mocked(getAccessToken).mockReturnValue('synthetic-session');
  reportFrontendDiagnostic('UI_EXPORT_FAILED'); reportFrontendDiagnostic('UI_EXPORT_FAILED');
  await Promise.resolve(); await Promise.resolve();
  expect(fetcher).toHaveBeenCalledOnce();
});

it('global handlers report a fixed error code and detach cleanly', async () => {
  const fetcher = vi.fn().mockResolvedValue({ ok: true }); vi.stubGlobal('fetch', fetcher);
  const { installFrontendDiagnostics } = await import('./frontendDiagnostics');
  const release = installFrontendDiagnostics();
  window.dispatchEvent(new ErrorEvent('error', { message: 'synthetic-secret', error: new Error('synthetic-secret') }));
  expect(fetcher).toHaveBeenCalledOnce();
  expect(fetcher.mock.calls[0][1].body).not.toContain('synthetic-secret');
  release();
  window.dispatchEvent(new Event('online'));
  expect(fetcher).toHaveBeenCalledOnce();
});
