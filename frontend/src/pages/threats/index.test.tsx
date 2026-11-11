import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import english from '@/locales/en-US';
import chinese from '@/locales/zh-CN';
import * as api from '@/services/honeypot/api';
import { exportExcel } from '@/utils/exportExcel';
import ThreatsPage from './index';

const session = vi.hoisted(() => ({ locale: 'zh-CN' }));
vi.mock('@umijs/max', () => ({
  request: vi.fn(),
  useIntl: () => ({
    locale: session.locale,
    formatMessage: ({ id, defaultMessage }: { id: string; defaultMessage?: string }) => {
      const messages: Record<string, string> = session.locale === 'zh-CN' ? chinese : english;
      return messages[id] ?? defaultMessage ?? id;
    },
  }),
}));
vi.mock('@/services/realtime', () => ({ connectHoneypotRealtime: vi.fn().mockResolvedValue(async () => {}) }));
vi.mock('@/services/honeypot/api', async (original) => ({ ...await original<typeof api>(), getThreats: vi.fn() }));
vi.mock('@/utils/exportExcel', () => ({ exportExcel: vi.fn().mockResolvedValue(undefined) }));

afterEach(cleanup);

it('localizes status tags and exports all loaded rows with the same status labels', async () => {
  const statuses = ['New', 'Observed', 'Suspicious', 'Blocked', 'Allowlisted', 'Muted', 'Expired', 'FutureStatus'];
  const items: api.ThreatIpProfile[] = Array.from({ length: 21 }, (_, index) => ({
    threatId: `threat-${index}`,
    sourceIp: `192.0.2.${index + 1}`,
    firstSeenUtc: '2026-01-01T00:00:00Z',
    lastSeenUtc: '2026-01-01T00:00:00Z',
    currentScore: 20,
    maxScore: 24,
    scoreVersion: 'v1',
    status: statuses[index] ?? 'Observed',
    attemptCount: 4,
    sessionCount: 2,
    activeSessionCount: 0,
    authenticationAttemptCount: 3,
    protocolViolationCount: 5,
    servicesTouched: ['rdp'],
    portsTouched: [3389],
    lastEventId: 'event-latest',
    lastReason: 'internal-detail',
    expiresAtUtc: '2026-02-01T00:00:00Z',
  }));
  vi.mocked(api.getThreats).mockResolvedValue({
    success: true,
    code: 'OK',
    message: '',
    data: { items, total: items.length, page: 1, pageSize: items.length },
  });

  const view = render(<ThreatsPage />);
  await screen.findByRole('columnheader', { name: '状态' });
  const labels = ['新发现', '已观察', '可疑', '已封禁', '白名单', '已静默', '已过期', '未知状态'];
  for (const label of labels) expect(screen.getAllByText(label).length).toBeGreaterThan(0);
  expect(screen.queryByText('FutureStatus')).not.toBeInTheDocument();
  expect(screen.queryByText('192.0.2.21')).not.toBeInTheDocument();
  const firstRow = screen.getByRole('row', { name: /^192\.0\.2\.1 / });
  expect(within(firstRow).getByRole('cell', { name: '3' })).toBeInTheDocument();

  fireEvent.click(screen.getByRole('button', { name: /导出 Excel/ }));
  await waitFor(() => expect(exportExcel).toHaveBeenCalledTimes(1));
  const [filename, sheetName, headers, rows] = vi.mocked(exportExcel).mock.calls[0];
  expect([filename, sheetName, headers[1]]).toEqual(['威胁清单', '威胁清单', '状态']);
  expect(rows).toHaveLength(21);
  expect(rows.slice(0, 8).map((row) => row[1])).toEqual(labels);
  expect(rows[20][0]).toBe('192.0.2.21');
  const firstExportRow = Object.fromEntries(headers.map((header, index) => [header, rows[0][index]]));
  expect(firstExportRow).toMatchObject({
    认证尝试: 3, 威胁编号: 'threat-0', 最近事件编号: 'event-latest',
    评分版本: 'v1', 会话总数: 2, 协议异常次数: 5, 到期时间: '2026/2/1 08:00:00',
  });
  expect(rows.flat()).not.toContain('internal-detail');

  session.locale = 'en-US';
  view.rerender(<ThreatsPage />);
  expect(screen.getByRole('columnheader', { name: 'Status' })).toBeInTheDocument();
  expect(screen.getByText('Blocked')).toBeInTheDocument();
  expect(screen.getByText('Unknown status')).toBeInTheDocument();
  expect(screen.queryByText('已封禁')).not.toBeInTheDocument();
});
