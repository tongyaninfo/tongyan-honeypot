import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import messages from '@/locales/zh-CN/events';
import * as api from '@/services/honeypot/api';
import CredentialEvidenceModal from './index';

vi.mock('@umijs/max', () => ({
  request: vi.fn(),
  useIntl: () => ({ formatMessage: ({ id }: { id: string }) => (messages as Record<string, string>)[id] ?? id }),
}));
vi.mock('@/services/honeypot/api', async (original) => ({ ...await original<typeof api>(), getCredentialEvidence: vi.fn() }));
const target = { artifactId: 'sample-artifact', adapterKey: 'ssh' };
const evidence = (password: string) => ({
  success: true, code: 'OK', message: '', data: {
    summary: { credentialArtifactId: target.artifactId, adapterKey: 'ssh', materialType: 'Plaintext', connectionId: 'conn-1', eventId: 'event-1', sourceIp: '192.0.2.1', capturedAtUtc: '2026-01-01T00:00:00Z' },
    content: JSON.stringify({ username: 'sample-user', password, method: 'password' }),
  },
});

describe('controlled credential viewer', () => {
  beforeEach(() => { vi.clearAllMocks(); });
  afterEach(cleanup);

  it('shows an actual captured password only while open and clears it on close', async () => {
    vi.mocked(api.getCredentialEvidence).mockResolvedValue(evidence('test-only-password'));
    const close = vi.fn();
    render(<CredentialEvidenceModal target={target} onClose={close} />);
    expect(await screen.findByText('test-only-password')).toBeInTheDocument();
    expect(localStorage.setItem).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('button', { name: 'Close' }));
    expect(close).toHaveBeenCalled();
    await waitFor(() => expect(screen.queryByText('test-only-password')).not.toBeInTheDocument());
  });

  it('distinguishes an empty password from response-only authentication', async () => {
    vi.mocked(api.getCredentialEvidence).mockResolvedValue(evidence(''));
    render(<CredentialEvidenceModal target={target} onClose={() => {}} />);
    expect(await screen.findByText('（空密码）')).toBeInTheDocument();
    expect(screen.queryByText(messages['events.evidence.noPassword'])).not.toBeInTheDocument();
  });

  it('ignores an in-flight secret response after the dialog has closed', async () => {
    let resolve: ((value: ReturnType<typeof evidence>) => void) | undefined;
    vi.mocked(api.getCredentialEvidence).mockImplementation(() => new Promise((done) => { resolve = done; }));
    const view = render(<CredentialEvidenceModal target={target} onClose={() => {}} />);
    await waitFor(() => expect(api.getCredentialEvidence).toHaveBeenCalledOnce());
    view.rerender(<CredentialEvidenceModal target={null} onClose={() => {}} />);
    await act(async () => { resolve?.(evidence('late-test-password')); });
    expect(screen.queryByText('late-test-password')).not.toBeInTheDocument();
    expect(api.getCredentialEvidence).toHaveBeenCalledOnce();
  });
});
