import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import chinese from '@/locales/zh-CN/events';
import * as api from '@/services/honeypot/api';
import { connectHoneypotRealtime } from '@/services/realtime';
import { exportExcel } from '@/utils/exportExcel';
import CredentialsPage from './index';

const session = vi.hoisted(() => ({ canAdmin: true }));
vi.mock('@umijs/max', () => ({
  request: vi.fn(),
  useAccess: () => session,
  useIntl: () => ({ locale: 'zh-CN', formatMessage: ({ id, defaultMessage }: { id: string; defaultMessage?: string }) => (chinese as Record<string, string>)[id] ?? defaultMessage ?? id }),
}));
vi.mock('@/services/realtime', () => ({ connectHoneypotRealtime: vi.fn().mockResolvedValue(async () => {}) }));
vi.mock('@/utils/exportExcel', async (original) => ({
  ...await original<typeof import('@/utils/exportExcel')>(),
  exportExcel: vi.fn().mockResolvedValue(undefined),
}));
vi.mock('@/services/honeypot/api', async (original) => ({
  ...await original<typeof api>(),
  getCredentialEvidenceSummaries: vi.fn(), exportCredentialEvidence: vi.fn(), getCredentialEvidence: vi.fn(),
}));

const summaries: api.CredentialEvidenceSummary[] = Array.from({ length: 9 }, (_, i) => ({
  credentialArtifactId: `cred-${i.toString(16).padStart(32, '0')}`, eventId: `event-${i}`, connectionId: `connection-${i}`,
  sourceIp: '192.0.2.1', adapterKey: i === 1 ? 'rdp' : 'ssh',
  materialType: ['Plaintext', 'Response', 'Decrypted'][i] ?? 'Plaintext', capturedAtUtc: '2026-01-01T00:00:00Z',
}));
const ok = <T,>(data: T) => ({ success: true, code: 'OK', message: '', data });

describe('credential evidence', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    session.canAdmin = true;
    vi.mocked(api.getCredentialEvidenceSummaries).mockResolvedValue(ok({ items: summaries, total: 9, page: 1, pageSize: 9 }));
    vi.mocked(api.getCredentialEvidence).mockRejectedValue(new Error('Evidence not found'));
  });
  afterEach(cleanup);

  it('uses the audited export endpoint and fills the workbook password column from captured plaintext', async () => {
    const password = '=sample-password';
    const content = JSON.stringify({ username: 'lab-user', password, material: 'a'.repeat(30000) + '🧪'.repeat(18000) });
    const longPassword = '🧪'.repeat(18000);
    const originals = [
      content,
      JSON.stringify({ username: 'lab-user', method: 'CredSSP/NTLM', response: 'sample-response' }),
      JSON.stringify({ password: '' }),
      JSON.stringify({ password: null }),
      JSON.stringify({ password: longPassword }),
    ];
    vi.mocked(api.exportCredentialEvidence).mockImplementation(async (ids) => ok({ items: ids.map((artifactId) => {
      const index = summaries.findIndex((row) => row.credentialArtifactId === artifactId);
      return originals[index] !== undefined
        ? { artifactId, outcome: 'OK', evidence: { summary: summaries[index], content: originals[index] } }
        : { artifactId, outcome: 'NOT_FOUND_OR_EXPIRED' };
    }) }));
    render(<CredentialsPage />);
    const button = await screen.findByRole('button', { name: '导出详细 Excel（含原文）' });
    await waitFor(() => expect(button).toBeEnabled());
    expect(api.exportCredentialEvidence).not.toHaveBeenCalled();
    const listReadCount = vi.mocked(api.getCredentialEvidence).mock.calls.length;
    fireEvent.click(button);
    await waitFor(() => expect(exportExcel).toHaveBeenCalledOnce());
    expect(vi.mocked(api.exportCredentialEvidence).mock.calls.map(([ids]) => ids.length)).toEqual([8, 1]);
    const [, , headers, summaryRows, sheets] = vi.mocked(exportExcel).mock.calls[0];
    expect(summaryRows).toHaveLength(9);
    const passwordColumn = headers.indexOf('密码');
    expect(passwordColumn).toBeGreaterThan(-1);
    expect(summaryRows.map((row) => row[passwordColumn])).toEqual([
      password, chinese['credentials.passwordNotCaptured'], chinese['events.evidence.emptyPassword'],
      chinese['credentials.passwordNotCaptured'], chinese['credentials.passwordSeeDetails'],
      ...Array.from({ length: 4 }, () => chinese['excel.unavailable']),
    ]);
    expect(sheets?.[0].rows).toContainEqual([summaries[0].credentialArtifactId, '已完成', '尝试登录的密码', 1, password]);
    const originalParts = sheets?.[0].rows.filter((row) => row[0] === summaries[0].credentialArtifactId && row[2] === '原始认证材料').map((row) => String(row[4])) ?? [];
    expect(originalParts).toHaveLength(3);
    expect(originalParts.join('')).toBe(content);
    expect(originalParts.every((part) => part.length <= 30000 && !/[\uD800-\uDBFF]$/.test(part))).toBe(true);
    const longPasswordParts = sheets?.[0].rows.filter((row) => row[0] === summaries[4].credentialArtifactId && row[2] === '尝试登录的密码').map((row) => String(row[4])) ?? [];
    expect(longPasswordParts.join('')).toBe(longPassword);
    expect(sheets?.[0].rows).toContainEqual([summaries[8].credentialArtifactId, '不存在或已过期']);
    expect(api.getCredentialEvidence).toHaveBeenCalledTimes(listReadCount);
  });

  it('does not offer detailed export to an analyst', async () => {
    session.canAdmin = false;
    render(<CredentialsPage />);
    await screen.findByText(summaries[0].credentialArtifactId);
    expect(screen.queryByRole('button', { name: '导出详细 Excel（含原文）' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: '显示密码' })).not.toBeInTheDocument();
    expect(api.exportCredentialEvidence).not.toHaveBeenCalled();
    expect(api.getCredentialEvidence).not.toHaveBeenCalled();
  });

  it('shows the original password automatically and leaves empty passwords and challenge responses blank', async () => {
    const password = '  dashboard-sample  ';
    const items = summaries.slice(0, 3);
    const summaryPage = { items, total: 3, page: 1, pageSize: 3 };
    vi.mocked(api.getCredentialEvidenceSummaries).mockResolvedValue(ok(summaryPage));
    vi.mocked(api.getCredentialEvidence).mockImplementation(async (id) => {
      const summary = items.find((item) => item.credentialArtifactId === id);
      if (!summary) throw new Error('Unexpected evidence request');
      return ok({ summary, content: JSON.stringify({ password: id === items[0].credentialArtifactId ? password : '' }) });
    });
    render(<CredentialsPage />);

    const displayed = await screen.findByText(password, { normalizer: (value) => value });
    expect(displayed.textContent).toBe(password);
    const passwordColumn = screen.getAllByRole('columnheader').findIndex((header) => header.textContent === '密码');
    for (const summary of items.slice(1)) {
      const row = screen.getByRole('row', { name: new RegExp(summary.credentialArtifactId) });
      expect(within(row).getAllByRole('cell')[passwordColumn]).toBeEmptyDOMElement();
    }
    expect(screen.queryByRole('button', { name: /^(显示|隐藏)密码$/ })).not.toBeInTheDocument();
    expect(vi.mocked(api.getCredentialEvidence).mock.calls.map(([id]) => id)).toEqual([items[0].credentialArtifactId, items[2].credentialArtifactId]);

    vi.mocked(api.getCredentialEvidenceSummaries).mockResolvedValue(ok({ ...summaryPage, items: items.map((item) => ({ ...item })) }));
    await act(async () => {
      vi.mocked(connectHoneypotRealtime).mock.calls[0][0].onEvent?.();
    });
    expect(api.getCredentialEvidenceSummaries).toHaveBeenCalledTimes(2);
    expect(api.getCredentialEvidence).toHaveBeenCalledTimes(2);
  });
});
