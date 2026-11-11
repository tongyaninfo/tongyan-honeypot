import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import access from './access';
import { getInitialState } from './app';
import LoginPage from './pages/auth/login';
import SetupPage from './pages/setup';
import * as identity from './services/identity';

const session = vi.hoisted(() => ({
  state: {} as { currentUser?: API.CurrentUser; initialized?: boolean },
  setInitialState: vi.fn(), replace: vi.fn(),
}));
vi.mock('@umijs/max', () => ({
  request: vi.fn(),
  history: { location: { pathname: '/events', search: '', hash: '' }, replace: session.replace },
  useModel: () => ({ setInitialState: session.setInitialState }),
  Link: ({ children }: { children: React.ReactNode }) => children,
}));
vi.mock('@/components', () => ({ Footer: () => null, LangDropdown: () => null, OfflineBanner: () => null, ErrorBoundary: ({ children }: { children: React.ReactNode }) => children }));
vi.mock('antd-style', () => ({ createStyles: () => () => ({ styles: {} }) }));
vi.mock('./requestErrorConfig', () => ({ errorConfig: {} }));
vi.mock('./services/identity', async (original) => ({
  ...await original<typeof identity>(),
  getSetupStatus: vi.fn(), getAccessToken: vi.fn(), getCurrentUser: vi.fn(),
  login: vi.fn(), initializeSystem: vi.fn(), setAccessToken: vi.fn(),
}));
const admin: identity.IdentityUser = { userId: 'sample-admin-id', username: 'sample-admin', roles: ['Administrator'] };
const ok = <T,>(data: T) => ({ success: true, code: 'OK', message: '', data });

describe('identity state across browser startup and login', () => {
  beforeEach(() => {
    vi.clearAllMocks(); session.state = {};
    session.setInitialState.mockImplementation(async (update) => { session.state = update(session.state); });
    vi.mocked(identity.getSetupStatus).mockResolvedValue(ok({ initialized: true }));
    vi.mocked(identity.getAccessToken).mockReturnValue('test-session-token');
    vi.mocked(identity.getCurrentUser).mockResolvedValue(ok(admin));
    vi.mocked(identity.login).mockResolvedValue(ok({ accessToken: 'test-session-token', expiresAtUtc: '2030-01-01T00:00:00Z', user: admin }));
    vi.mocked(identity.initializeSystem).mockResolvedValue(ok(admin));
  });
  afterEach(cleanup);

  it('loads real /auth/me identity fields and admin roles after refresh', async () => {
    const state = await getInitialState();
    expect(state.currentUser?.name).toBe('sample-admin');
    expect(state.currentUser?.userid).toBe('sample-admin-id');
    expect(access(state).canAdmin).toBe(true);
  });

  it('keeps a real reader identity non-admin after refresh', async () => {
    vi.mocked(identity.getCurrentUser).mockResolvedValue(ok({ ...admin, roles: ['Analyst'] }));
    expect(access(await getInitialState()).canAdmin).toBe(false);
  });

  it('updates permissions before client-side navigation after login', async () => {
    render(<LoginPage />);
    fireEvent.change(screen.getByLabelText('用户名'), { target: { value: 'sample-admin' } });
    fireEvent.change(screen.getByLabelText('密码'), { target: { value: 'test-only-password' } });
    fireEvent.click(screen.getByRole('button', { name: '登录管理平台' }));
    await waitFor(() => expect(session.replace).toHaveBeenCalledWith('/overview'));
    expect(access(session.state).canAdmin).toBe(true);
    expect(session.state.initialized).toBe(true);
    expect(session.setInitialState.mock.invocationCallOrder[0]).toBeLessThan(session.replace.mock.invocationCallOrder[0]);
  });

  it('updates the first administrator identity after setup without requiring a refresh', async () => {
    render(<SetupPage />);
    fireEvent.change(screen.getByLabelText('管理员账号'), { target: { value: 'sample-admin' } });
    fireEvent.change(screen.getByLabelText('密码'), { target: { value: 'test-only-password' } });
    fireEvent.change(screen.getByLabelText('确认密码'), { target: { value: 'test-only-password' } });
    fireEvent.click(screen.getByRole('button', { name: '完成初始化' }));
    await waitFor(() => expect(session.replace).toHaveBeenCalledWith('/overview'));
    expect(access(session.state).canAdmin).toBe(true);
    expect(session.state.currentUser?.name).toBe('sample-admin');
  });
});
