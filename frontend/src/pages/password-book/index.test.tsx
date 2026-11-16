import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import messages from '@/locales/zh-CN';
import {
  exportCredentialEvidence,
  getCredentialEvidence,
  getPasswordBook,
  type ApiResult,
  type CredentialEvidenceExportItem,
  type CredentialEvidenceView,
  type PageResult,
  type PasswordBookRow,
} from '@/services/honeypot/api';
import { exportCsv } from '@/utils/exportCsv';
import PasswordBookPage from './index';

const access = vi.hoisted(() => ({ canAdmin: true }));
vi.mock('@umijs/max', () => ({
  request: vi.fn(),
  useAccess: () => access,
  useIntl: () => ({
    locale: 'zh-CN',
    formatMessage: (
      {
        id,
        defaultMessage,
      }: { id: keyof typeof messages; defaultMessage?: string },
      values?: Record<string, number>,
    ) =>
      (messages[id] ?? defaultMessage ?? id).replace(/\{(\w+)\}/g, (_, key) =>
        String(values?.[key] ?? ''),
      ),
    formatNumber: (value: number) => value.toLocaleString('zh-CN'),
  }),
}));
vi.mock('@/services/honeypot/api', async (original) => ({
  ...(await original<typeof import('@/services/honeypot/api')>()),
  exportCredentialEvidence: vi.fn(),
  getCredentialEvidence: vi.fn(),
  getPasswordBook: vi.fn(),
}));
vi.mock('@/utils/exportCsv', () => ({ exportCsv: vi.fn() }));

const readEvidence = vi.mocked(getCredentialEvidence);
const getPage = vi.mocked(getPasswordBook);
const readExport = vi.mocked(exportCredentialEvidence);
const downloadCsv = vi.mocked(exportCsv);
const lastUsedAtUtc = '2026-11-15T01:30:00Z';

const ok = <T,>(data: T): ApiResult<T> => ({
  success: true,
  code: 'OK',
  message: '',
  data,
});

function row(username: string) {
  return {
    username,
    adapterKey: 'redis',
    authenticationCount: 5,
    lastUsedAtUtc,
    credentialArtifactId: `evidence-${username}`,
  };
}

function evidence(id: string, password: string, retentionUntilUtc?: string) {
  return ok({
    summary: {
      credentialArtifactId: id,
      connectionId: 'connection-demo',
      eventId: 'event-demo',
      sourceIp: '192.0.2.1',
      adapterKey: 'redis',
      materialType: 'Plaintext',
      capturedAtUtc: lastUsedAtUtc,
      retentionUntilUtc,
    },
    content: JSON.stringify({ password }),
  });
}

afterEach(() => {
  cleanup();
  getPage.mockReset();
  readEvidence.mockReset();
  readExport.mockReset();
  downloadCsv.mockReset();
  access.canAdmin = true;
});

it('逐条读取并直接显示密码，区分空密码，失效证据不影响其他行', async () => {
  const items = ['demo-user', 'demo-empty', 'demo-error', 'demo-expired'].map(
    row,
  );
  getPage.mockResolvedValue(
    ok({ items, total: items.length, page: 1, pageSize: 20 }),
  );
  readEvidence.mockImplementation(async (id) => {
    if (id === 'evidence-demo-error')
      throw new Error('Sample evidence unavailable');
    if (id === 'evidence-demo-expired')
      return evidence(id, 'sample-expired', '2000-01-01T00:00:00Z');
    return evidence(
      id,
      id === 'evidence-demo-empty' ? '' : '  sample<value>  ',
    );
  });

  render(<PasswordBookPage />);
  expect(screen.getByRole('heading', { name: '密码簿' })).toBeInTheDocument();
  expect(await screen.findByText('（空密码）')).toBeInTheDocument();
  expect(await screen.findAllByText('证据不可用或已过期')).toHaveLength(2);
  const displayedRow = screen.getByRole('row', { name: /^demo-user / });
  expect(displayedRow.querySelector('code')?.textContent).toBe(
    '  sample<value>  ',
  );
  expect(
    within(displayedRow).getByRole('cell', { name: 'REDIS' }),
  ).toBeInTheDocument();
  expect(
    within(displayedRow).getByRole('cell', { name: '5' }),
  ).toBeInTheDocument();
  expect(displayedRow.querySelector('time')).toHaveTextContent('09:30:00');
  expect(screen.queryByText('sample-expired')).not.toBeInTheDocument();
  expect(getPage).toHaveBeenCalledWith(
    { page: 1, pageSize: 20 },
    expect.any(AbortSignal),
  );
  expect(readEvidence.mock.calls.map(([id]) => id)).toEqual(
    items.map((item) => item.credentialArtifactId),
  );
});

it('切页马上清除旧页密码并取消旧读取，退出时清理当前页', async () => {
  let finishOldRead: (value: ApiResult<CredentialEvidenceView>) => void =
    () => {};
  getPage.mockResolvedValueOnce(
    ok({
      items: [row('demo-old'), row('demo-pending')],
      total: 21,
      page: 1,
      pageSize: 20,
    }),
  );
  getPage.mockResolvedValueOnce(
    ok({ items: [row('demo-new')], total: 21, page: 2, pageSize: 20 }),
  );
  readEvidence.mockImplementation((id) => {
    if (id === 'evidence-demo-pending')
      return new Promise((resolve) => {
        finishOldRead = resolve;
      });
    return Promise.resolve(
      evidence(id, id === 'evidence-demo-old' ? 'sample-old' : 'sample-new'),
    );
  });

  const page = render(<PasswordBookPage />);
  expect(await screen.findByText('sample-old')).toBeInTheDocument();
  fireEvent.click(screen.getByTitle('2'));
  expect(screen.queryByText('sample-old')).not.toBeInTheDocument();
  const pendingSignal = readEvidence.mock.calls.find(
    ([id]) => id === 'evidence-demo-pending',
  )?.[1]?.signal as AbortSignal;
  expect(pendingSignal.aborted).toBe(true);

  await act(async () =>
    finishOldRead(evidence('evidence-demo-pending', 'sample-late')),
  );
  expect(screen.queryByText('sample-late')).not.toBeInTheDocument();
  expect(await screen.findByText('sample-new')).toBeInTheDocument();
  expect(getPage).toHaveBeenLastCalledWith(
    { page: 2, pageSize: 20 },
    expect.any(AbortSignal),
  );
  const lastSignal = readEvidence.mock.lastCall?.[1]?.signal as AbortSignal;
  page.unmount();
  expect(lastSignal.aborted).toBe(true);
  expect(screen.queryByText('sample-new')).not.toBeInTheDocument();
});

it('非管理员直接访问页面时不查询密码簿或证据', () => {
  access.canAdmin = false;
  render(<PasswordBookPage />);
  expect(screen.getByRole('alert')).toHaveTextContent('仅管理员可访问密码簿。');
  expect(getPage).not.toHaveBeenCalled();
  expect(readEvidence).not.toHaveBeenCalled();
  expect(readExport).not.toHaveBeenCalled();
  expect(
    screen.queryByRole('button', { name: '导出 CSV（含密码）' }),
  ).not.toBeInTheDocument();
});

it('搜索和清空回到第一页，并丢弃旧筛选的迟到结果', async () => {
  let finishStaleSearch: (
    value: ApiResult<PageResult<PasswordBookRow>>,
  ) => void = () => {};
  getPage.mockImplementation(({ page = 1, keyword }) => {
    if (keyword === 'stale') {
      return new Promise((resolve) => {
        finishStaleSearch = resolve;
      });
    }
    if (keyword === 'redis') {
      return Promise.resolve(ok({ items: [], total: 0, page, pageSize: 20 }));
    }
    return Promise.resolve(
      ok({
        items: [row(`unfiltered-${page}`)],
        total: 21,
        page,
        pageSize: 20,
      }),
    );
  });
  readEvidence.mockImplementation(async (id) => evidence(id, `sample-${id}`));

  render(<PasswordBookPage />);
  await screen.findByText('unfiltered-1');
  fireEvent.click(screen.getByTitle('2'));
  const oldPassword = await screen.findByText('sample-evidence-unfiltered-2');
  const oldPasswordSignal = readEvidence.mock.lastCall?.[1]
    ?.signal as AbortSignal;
  const input = screen.getByRole('textbox', { name: '按账号或服务搜索' });
  const search = screen.getByRole('button', { name: /^搜\s?索$/ });

  fireEvent.change(input, { target: { value: '  stale  ' } });
  fireEvent.click(search);
  expect(oldPassword).not.toBeInTheDocument();
  expect(oldPasswordSignal.aborted).toBe(true);
  expect(getPage).toHaveBeenLastCalledWith(
    { page: 1, pageSize: 20, keyword: 'stale' },
    expect.any(AbortSignal),
  );
  const staleSignal = getPage.mock.lastCall?.[1];

  fireEvent.change(input, { target: { value: 'redis' } });
  fireEvent.click(search);
  expect(staleSignal?.aborted).toBe(true);
  await screen.findByText('未找到匹配的密码记录');
  await act(async () =>
    finishStaleSearch(
      ok({
        items: [row('stale-result')],
        total: 1,
        page: 1,
        pageSize: 20,
      }),
    ),
  );
  expect(screen.queryByText('stale-result')).not.toBeInTheDocument();

  fireEvent.click(screen.getByRole('button', { name: /^清\s?空$/ }));
  expect(input).toHaveValue('');
  expect(await screen.findByText('unfiltered-1')).toBeInTheDocument();
  expect(getPage).toHaveBeenLastCalledWith(
    { page: 1, pageSize: 20 },
    expect.any(AbortSignal),
  );
});

it('从已应用的筛选导出全部结果，按批审计并区分空密码与不可用证据', async () => {
  const matches = Array.from({ length: 21 }, (_, index) =>
    row(`match-${index}`),
  );
  getPage.mockImplementation(async ({ page = 1, pageSize = 20, keyword }) => {
    const items = keyword === 'match' ? matches : [row('unfiltered')];
    return ok({
      items: items.slice((page - 1) * pageSize, page * pageSize),
      total: items.length,
      page,
      pageSize,
    });
  });
  readEvidence.mockImplementation(async (id) => evidence(id, `sample-${id}`));
  readExport.mockImplementation(async (ids) =>
    ok({
      items: ids.map((artifactId): CredentialEvidenceExportItem => {
        const index = matches.findIndex(
          (item) => item.credentialArtifactId === artifactId,
        );
        if (index === 2)
          return { artifactId, outcome: 'EVIDENCE_AUDIT_FAILED' };
        const captured = evidence(
          index === 3 ? 'mismatched-summary' : artifactId,
          index === 1 ? '' : 'audit-sample',
          index === 6 ? '2000-01-01T00:00:00Z' : undefined,
        ).data;
        if (index === 5) captured.summary.materialType = 'Response';
        return {
          artifactId: index === 4 ? 'mismatched-item' : artifactId,
          outcome: 'OK',
          evidence: captured,
        };
      }),
    }),
  );

  render(<PasswordBookPage />);
  await screen.findByText('unfiltered');
  const input = screen.getByRole('textbox', { name: '按账号或服务搜索' });
  fireEvent.change(input, { target: { value: 'match' } });
  fireEvent.click(screen.getByRole('button', { name: /^搜\s?索$/ }));
  await screen.findByText('match-0');
  fireEvent.click(screen.getByTitle('2'));
  await screen.findByText('match-20');
  expect(screen.queryByText('match-0')).not.toBeInTheDocument();
  fireEvent.change(input, { target: { value: 'draft' } });
  fireEvent.click(screen.getByRole('button', { name: '导出 CSV（含密码）' }));

  await waitFor(() => expect(downloadCsv).toHaveBeenCalledOnce());
  expect(getPage).toHaveBeenLastCalledWith(
    { page: 1, pageSize: 100, keyword: 'match' },
    expect.any(AbortSignal),
  );
  expect(readExport.mock.calls.map(([ids]) => ids.length)).toEqual([8, 8, 5]);
  expect(readExport.mock.calls.flatMap(([ids]) => ids)).toEqual(
    matches.map((item) => item.credentialArtifactId),
  );
  const [filename, headers, rows] = downloadCsv.mock.calls[0];
  expect(filename).toBe('password-book');
  expect(headers).toEqual([
    '账号',
    '密码',
    '服务',
    '认证次数',
    '最近一次使用时间（UTC）',
    '证据状态',
  ]);
  expect(rows.map(([username]) => username)).toEqual(
    matches.map((item) => item.username),
  );
  expect(rows[0]).toEqual([
    'match-0',
    'audit-sample',
    'REDIS',
    5,
    lastUsedAtUtc,
    '可用',
  ]);
  expect(rows[1]).toEqual(['match-1', '', 'REDIS', 5, lastUsedAtUtc, '可用']);
  for (const [, password, , , , status] of rows.slice(2, 7)) {
    expect(password).toBe('');
    expect(status).toBe('证据不可用或已过期');
  }
  expect(
    screen.getByText('已导出 21 条记录，其中 5 条密码不可用。'),
  ).toBeInTheDocument();
});

it('离开时取消证据导出，迟到的结果不会下载', async () => {
  let finishExport: (
    value: ApiResult<{ items: CredentialEvidenceExportItem[] }>,
  ) => void = () => {};
  getPage.mockResolvedValue(
    ok({ items: [row('demo')], total: 1, page: 1, pageSize: 20 }),
  );
  readEvidence.mockImplementation(async (id) => evidence(id, 'sample'));
  readExport.mockImplementation(
    () =>
      new Promise((resolve) => {
        finishExport = resolve;
      }),
  );

  const view = render(<PasswordBookPage />);
  await screen.findByText('demo');
  const button = screen.getByRole('button', { name: '导出 CSV（含密码）' });
  fireEvent.click(button);
  await waitFor(() => expect(readExport).toHaveBeenCalledOnce());
  expect(button).toBeDisabled();
  expect(getPage).toHaveBeenLastCalledWith(
    { page: 1, pageSize: 100 },
    expect.any(AbortSignal),
  );
  const signal = readExport.mock.lastCall?.[1];
  view.unmount();
  expect(signal?.aborted).toBe(true);
  await act(async () =>
    finishExport(
      ok({
        items: [
          {
            artifactId: 'evidence-demo',
            outcome: 'OK',
            evidence: evidence('evidence-demo', 'late-sample').data,
          },
        ],
      }),
    ),
  );
  expect(downloadCsv).not.toHaveBeenCalled();
});
