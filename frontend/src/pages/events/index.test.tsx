import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import access from '@/access';
import { toCurrentUser } from '@/services/identity';
import english from '@/locales/en-US/events';
import chinese from '@/locales/zh-CN/events';
import * as api from '@/services/honeypot/api';
import { exportExcel } from '@/utils/exportExcel';
import EventsPage from './index';

const session = vi.hoisted(() => ({ locale: 'zh-CN', roles: ['Administrator'], search: '' }));
vi.mock('@umijs/max', () => ({
  request: vi.fn(),
  useAccess: () => access({ currentUser: toCurrentUser({ userId: 'sample-user-id', username: 'sample-user', roles: session.roles }) }),
  useLocation: () => ({ search: session.search }),
  useIntl: () => ({
    locale: session.locale,
    formatMessage: ({ id, defaultMessage }: { id: string; defaultMessage?: string }, values?: Record<string, unknown>) => {
      const messages: Record<string, string> = session.locale === 'zh-CN' ? chinese : english;
      return (messages[id] ?? defaultMessage ?? id).replace(/\{(\w+)\}/g, (_, key) => String(values?.[key] ?? ''));
    },
  }),
}));
vi.mock('@/services/realtime', () => ({ connectHoneypotRealtime: vi.fn().mockResolvedValue(async () => {}) }));
vi.mock('@/utils/exportExcel', () => ({ exportExcel: vi.fn().mockResolvedValue(undefined) }));
vi.mock('@/services/honeypot/api', async (original) => ({
  ...await original<typeof api>(),
  getEvents: vi.fn(), getConnectionEvents: vi.fn(), getCredentialEvidence: vi.fn(),
}));

const login: api.InteractionEvent = {
  eventId: 'evt-login', connectionId: 'conn-1', sequence: 7,
  eventType: 'AuthenticationAttempted', occurredAtUtc: '2026-01-01T00:00:00Z',
  sourceIp: '192.0.2.1', destinationPort: 3389, adapterKey: 'rdp', serviceInstanceId: 'rdp-test', listenerId: 'listener-test',
  username: 'sample-user', domain: 'LAB', authenticationMethod: 'CredSSP/NTLM',
  authenticationFailureCode: 'STATUS_LOGON_FAILURE', authenticationAttempt: 1,
  outcome: 'failure', materialType: 'Response', credentialCaptureStatus: 'Captured', credentialArtifactId: 'artifact-1', eventCount: 8,
};
const ok = <T,>(data: T) => ({ success: true, code: 'OK', message: '', data });

describe('threat activity list', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    session.locale = 'zh-CN'; session.roles = ['Administrator']; session.search = '';
    vi.mocked(api.getEvents).mockResolvedValue(ok({ items: [login], total: 1, page: 1, pageSize: 50 }));
    vi.mocked(api.getConnectionEvents).mockResolvedValue(ok([
      { ...login, eventId: 'evt-start', eventType: 'ConnectionAccepted' },
      { ...login, eventId: 'evt-tls', eventType: 'TlsHandshakeCompleted' },
      { ...login, eventId: 'evt-challenge', eventType: 'CredSspChallengeSent' },
      login,
      { ...login, eventId: 'evt-close', eventType: 'SessionClosed' },
    ]));
  });
  afterEach(cleanup);

  it('requests one activity row with auth metadata and does not preload passwords', async () => {
    render(<EventsPage />);
    expect(await screen.findByText('LAB\\sample-user')).toBeInTheDocument();
    expect(api.getEvents).toHaveBeenCalledWith(expect.objectContaining({ view: 'activity' }));
    expect(screen.getByText('登录失败')).toBeInTheDocument();
    expect(screen.getByText('CredSSP/NTLM')).toBeInTheDocument();
    expect(screen.getByText('STATUS_LOGON_FAILURE')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: '8 个步骤' })).toBeInTheDocument();
    expect(screen.queryByText('SessionClosed')).not.toBeInTheDocument();
    expect(api.getCredentialEvidence).not.toHaveBeenCalled();
  });

  it('translates event labels when the selected language changes', async () => {
    const view = render(<EventsPage />);
    await screen.findByText('登录失败');
    session.locale = 'en-US';
    view.rerender(<EventsPage />);
    expect(screen.getByText('Login failed')).toBeInTheDocument();
    expect(screen.queryByText('登录失败')).not.toBeInTheDocument();
  });

  it('applies linked filters immediately and restores them as the URL changes', async () => {
    const initialSearch = '?sourceIp=192.0.2.1&eventType=AuthenticationAttempted';
    session.search = initialSearch;
    const view = render(<EventsPage />);
    await screen.findByText('CredSSP/NTLM');
    expect(api.getEvents).toHaveBeenNthCalledWith(1, expect.objectContaining({
      sourceIp: '192.0.2.1', eventType: 'AuthenticationAttempted', view: 'activity',
    }));

    session.search = '?sourceIp=2001%3Adb8%3A%3A1';
    view.rerender(<EventsPage />);
    expect(screen.getByPlaceholderText('来源 IP')).toHaveValue('2001:db8::1');
    await screen.findByText('CredSSP/NTLM');
    expect(api.getEvents).toHaveBeenLastCalledWith(expect.objectContaining({ sourceIp: '2001:db8::1', eventType: undefined }));

    session.search = initialSearch;
    view.rerender(<EventsPage />);
    expect(screen.getByPlaceholderText('来源 IP')).toHaveValue('192.0.2.1');
    await screen.findByText('CredSSP/NTLM');
    expect(api.getEvents).toHaveBeenLastCalledWith(expect.objectContaining({ sourceIp: '192.0.2.1', eventType: 'AuthenticationAttempted' }));
  });

  it('exports filtered activity across pages and only the steps for those connections', async () => {
    const filtered = Array.from({ length: 21 }, (_, i) => ({ ...login, eventId: `activity-${i}` }));
    const step = { ...login, eventId: 'step-match', eventType: 'TlsHandshakeCompleted', sequence: 2 };
    const other = { ...step, connectionId: 'different-connection', eventId: 'step-unmatched' };
    vi.mocked(api.getEvents).mockImplementation(async (query) => {
      const items = query?.view === 'raw' ? [other, step] : query?.sourceIp === login.sourceIp ? filtered : [login];
      return ok({ items, total: items.length, page: 1, pageSize: items.length });
    });
    render(<EventsPage />);
    await screen.findByText('登录失败');
    fireEvent.change(screen.getByPlaceholderText('来源 IP'), { target: { value: login.sourceIp } });
    await waitFor(() => expect(api.getEvents).toHaveBeenCalledWith(expect.objectContaining({ sourceIp: login.sourceIp, view: 'activity' })));
    const button = screen.getByRole('button', { name: '导出 Excel' });
    await waitFor(() => expect(button).toBeEnabled());
    fireEvent.click(button);
    await waitFor(() => expect(exportExcel).toHaveBeenCalledOnce());
    const [filename, , headers, activities, sheets] = vi.mocked(exportExcel).mock.calls[0];
    expect(filename).toBe('threat-events');
    expect(activities).toHaveLength(21);
    expect(headers).toContain('认证方式');
    expect(sheets?.[0].rows).toHaveLength(1);
    expect(sheets?.[0].rows[0]).toEqual(expect.arrayContaining(['安全握手完成', 'step-match']));
    expect(api.getCredentialEvidence).not.toHaveBeenCalled();
  });

  it('shows localized lifecycle steps only in connection details', async () => {
    render(<EventsPage />);
    fireEvent.click(await screen.findByRole('button', { name: '8 个步骤' }));
    expect(await screen.findByText('安全握手完成')).toBeInTheDocument();
    expect(screen.getByText('凭据认证挑战已发送')).toBeInTheDocument();
    expect(screen.getByText('会话关闭')).toBeInTheDocument();
    expect(api.getConnectionEvents).toHaveBeenCalledWith('conn-1');
    expect(api.getCredentialEvidence).not.toHaveBeenCalled();
  });

  it('does not offer raw credential access to non-admin users', async () => {
    session.roles = ['Analyst'];
    render(<EventsPage />);
    await screen.findByText('仅管理员可查看原文');
    expect(screen.queryByRole('button', { name: '查看账号密码' })).not.toBeInTheDocument();
    expect(api.getCredentialEvidence).not.toHaveBeenCalled();
  });

  it('loads response evidence only after explicit viewing and explains unavailable RDP plaintext', async () => {
    vi.mocked(api.getCredentialEvidence).mockResolvedValue(ok({
      summary: { credentialArtifactId: 'artifact-1', connectionId: 'conn-1', eventId: 'evt-login', sourceIp: '192.0.2.1', adapterKey: 'rdp', materialType: 'Response', capturedAtUtc: login.occurredAtUtc },
      content: JSON.stringify({ username: 'sample-user', domain: 'LAB', method: 'NTLM', authenticate: 'sample-response' }),
    }));
    render(<EventsPage />);
    fireEvent.click(await screen.findByRole('button', { name: '查看账号密码' }));
    expect(await screen.findByText(chinese['events.evidence.ntlm'])).toBeInTheDocument();
    expect(api.getCredentialEvidence).toHaveBeenCalledWith('artifact-1', expect.objectContaining({ signal: expect.any(AbortSignal) }));
    fireEvent.click(screen.getByRole('button', { name: 'Close' }));
    await waitFor(() => expect(screen.queryByText(chinese['events.evidence.ntlm'])).not.toBeInTheDocument());
  });
});
