import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import {
  getCredentialEvidence,
  getOverviewConnections,
  type OverviewConnectionRow,
  type OverviewConnectionScope,
  resolveIPLocations,
} from '@/services/honeypot/api';
import { ipLocationClient } from '@/services/honeypot/ipLocationClient';
import { AdapterActivityCard } from './OverviewActivityTables';
import OverviewConnectionsPopover from './OverviewConnectionsPopover';
import OverviewHeader from './OverviewHeader';

const access = vi.hoisted(() => ({ canAdmin: true }));
vi.mock('@umijs/max', () => ({ useAccess: () => access, Link: () => null }));
vi.mock('@/services/honeypot/api', () => ({
  getOverviewConnections: vi.fn(),
  getCredentialEvidence: vi.fn(),
  maxIPLocationInputLength: 80,
  resolveIPLocations: vi.fn(),
}));

const getConnections = vi.mocked(getOverviewConnections);
const getEvidence = vi.mocked(getCredentialEvidence);
const getLocations = vi.mocked(resolveIPLocations);

it('提示用户刷新已过期的活动连接快照', async () => {
  getConnections.mockRejectedValue({ response: { status: 410 } });
  render(<OverviewConnectionsPopover label="活动连接" scope="active" asOfUtc="2026-11-15T01:00:00Z">活动连接</OverviewConnectionsPopover>);
  fireEvent.click(screen.getByRole('button', { name: '活动连接' }));
  expect(await screen.findByText('活动连接快照已过期，请刷新首页后重新打开明细。')).toBeInTheDocument();
});

beforeEach(() => {
  getLocations.mockImplementation(async (ips) => ({
    success: true,
    code: 'OK',
    message: '',
    data: {
      enabled: true,
      items: ips.map((ip) => ({
        ip,
        status: 'resolved',
        country: '示例国家',
        city: '示例城市',
      })),
    },
  }));
});

afterEach(() => {
  cleanup();
  ipLocationClient.invalidate();
  access.canAdmin = true;
  getConnections.mockReset();
  getEvidence.mockReset();
  getLocations.mockReset();
});

it('首页卡片采用近 24 小时接纳数以及有可追溯连接的来源数', () => {
  render(<OverviewHeader metricsAvailable loading={false} metrics={{
    generatedAtUtc: '2026-11-15T01:30:00Z', eventCount: 20, acceptedConnections: 8, acceptedCount: 120,
    authenticationAttempts: 0, authenticationFailures: 0, protocolViolations: 0, sessionClosed: 0,
    threatIpCount: 5, traceableThreatIpCount: 3, serviceInstanceCount: 1, listenerCount: 1,
    runningListenerCount: 1, failedListenerCount: 0, activeConnections: 1, listenerErrorCount: 0,
    eventsByAdapter: [], eventsByOutcome: [], eventsByHour: [], listeners: [],
  }} />);
  expect(screen.getByRole('button', { name: /近 24 小时接纳连接/ })).toHaveTextContent('8');
  expect(screen.getByRole('button', { name: /威胁 IP/ })).toHaveTextContent('3');
  expect(screen.getByText('另有 2 个活跃档案缺少留存的连接明细')).toBeInTheDocument();
});

function result(
  page: number,
  sourceIp: string,
  additional: Partial<OverviewConnectionRow> = {},
) {
  return {
    success: true,
    code: 'OK',
    message: '',
    data: {
      page,
      pageSize: 5,
      total: 6,
      items: [
        {
          id: `row-${page}`,
          connectionId: `connection-${page}`,
          occurredAtUtc: '2026-11-15T01:30:00Z',
          sourceIp,
          adapterKey: 'redis',
          destinationPort: 6379,
          ...additional,
        },
      ],
    },
  };
}

function evidence(artifactId: string, password: string) {
  return {
    success: true,
    code: 'OK',
    message: '',
    data: {
      summary: {
        credentialArtifactId: artifactId,
        eventId: 'test-event',
        connectionId: 'test-connection',
        sourceIp: '192.0.2.1',
        adapterKey: 'redis',
        materialType: 'Plaintext',
        capturedAtUtc: '2026-11-15T01:30:00Z',
      },
      content: JSON.stringify({ password }),
    },
  };
}

it('悬停加载对应指标，移入气泡后可以翻页，关闭重开返回第一页', async () => {
  let finishSecond: (value: ReturnType<typeof result>) => void = () => {};
  getConnections
    .mockResolvedValueOnce(result(1, '192.0.2.1'))
    .mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          finishSecond = resolve;
        }),
    )
    .mockResolvedValueOnce(result(1, '192.0.2.1'));
  const cardAt = (asOfUtc: string) => <OverviewConnectionsPopover label="活动连接" scope="active" asOfUtc={asOfUtc}>
    活动连接
  </OverviewConnectionsPopover>;
  const first = '2026-11-15T01:00:00Z';
  const refreshed = '2026-11-15T01:01:00Z';
  const view = render(cardAt(first));
  const trigger = screen.getByRole('button', { name: '活动连接' });
  expect(getConnections).not.toHaveBeenCalled();

  fireEvent.mouseEnter(trigger);
  expect(await screen.findByText('192.0.2.1')).toBeInTheDocument();
  expect(getConnections).toHaveBeenLastCalledWith({
    scope: 'active',
    asOfUtc: first,
    page: 1,
    pageSize: 5,
  });

  const popup = screen.getByRole('dialog', { name: '活动连接' });
  view.rerender(cardAt(refreshed));
  fireEvent.mouseLeave(trigger);
  fireEvent.mouseEnter(popup);
  fireEvent.click(screen.getByTitle('2'));
  expect(getConnections).toHaveBeenLastCalledWith({
    scope: 'active',
    asOfUtc: first,
    page: 2,
    pageSize: 5,
  });
  // 等待超过离开触发按钮后的关闭延时，验证分页加载中气泡仍在。
  await act(async () => new Promise((resolve) => setTimeout(resolve, 250)));
  expect(popup).toBeInTheDocument();
  expect(screen.getByText('192.0.2.1')).toBeInTheDocument();
  await act(async () => finishSecond(result(2, '192.0.2.2')));
  expect(await screen.findByText('192.0.2.2')).toBeInTheDocument();

  fireEvent.keyDown(popup, { key: 'Escape' });
  expect(trigger).toHaveFocus();
  expect(trigger).toHaveAttribute('aria-expanded', 'false');
  fireEvent.click(trigger);
  expect(await screen.findByText('192.0.2.1')).toBeInTheDocument();
  expect(getConnections).toHaveBeenLastCalledWith({ scope: 'active', asOfUtc: refreshed, page: 1, pageSize: 5 });
});

it('关闭后迟到的旧请求不会覆盖重开的明细', async () => {
  let finishFirst: (value: ReturnType<typeof result>) => void = () => {};
  getConnections
    .mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          finishFirst = resolve;
        }),
    )
    .mockResolvedValueOnce(result(1, '192.0.2.2'));
  render(
    <OverviewConnectionsPopover label="威胁 IP" scope="threatConnections">
      威胁 IP
    </OverviewConnectionsPopover>,
  );
  const trigger = screen.getByRole('button', { name: '威胁 IP' });
  fireEvent.click(trigger);
  await waitFor(() => expect(getConnections).toHaveBeenCalledTimes(1));
  fireEvent.click(trigger);
  fireEvent.click(trigger);
  expect(await screen.findByText('192.0.2.2')).toBeInTheDocument();
  expect(getConnections).toHaveBeenLastCalledWith({
    scope: 'threatConnections',
    page: 1,
    pageSize: 5,
  });
  await act(async () => finishFirst(result(1, '192.0.2.1')));
  expect(screen.queryByText('192.0.2.1')).not.toBeInTheDocument();
  expect(screen.getByText('192.0.2.2')).toBeInTheDocument();
});

it.each<OverviewConnectionScope>([
  'active',
  'accepted',
  'authenticationFailures',
  'threatConnections',
])('%s 的归属地使用现有 IP 解析，并和来源 IP 分开显示', async (scope) => {
  getConnections.mockResolvedValue(result(1, '192.0.2.1'));
  render(
    <OverviewConnectionsPopover label="连接明细" scope={scope}>
      连接明细
    </OverviewConnectionsPopover>,
  );
  fireEvent.click(screen.getByRole('button', { name: '连接明细' }));
  const dialog = within(await screen.findByRole('dialog'));
  expect(
    dialog.getByRole('columnheader', { name: '归属地' }),
  ).toBeInTheDocument();
  expect(
    await dialog.findByRole('cell', { name: '192.0.2.1' }),
  ).toBeInTheDocument();
  expect(
    await dialog.findByRole('cell', { name: '示例国家 · 示例城市' }),
  ).toBeInTheDocument();
  expect(getLocations).toHaveBeenCalledExactlyOnceWith(
    ['192.0.2.1'],
    expect.any(AbortSignal),
  );
  if (scope !== 'authenticationFailures') {
    expect(
      dialog.queryByRole('columnheader', { name: '账号' }),
    ).not.toBeInTheDocument();
    expect(
      dialog.queryByRole('columnheader', { name: '密码' }),
    ).not.toBeInTheDocument();
  }
  expect(getEvidence).not.toHaveBeenCalled();
});

it('认证失败当前页逐条读取密码，切页去掉旧密码，关闭气泡时卸载空密码显示', async () => {
  let finishSecond: (value: ReturnType<typeof result>) => void = () => {};
  getConnections
    .mockResolvedValueOnce(
      result(1, '192.0.2.1', {
        username: 'fixture-user',
        credentialArtifactId: 'fixture-evidence-first',
        materialType: 'Plaintext',
      }),
    )
    .mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          finishSecond = resolve;
        }),
    );
  getEvidence
    .mockResolvedValueOnce(
      evidence('fixture-evidence-first', 'fixture-password'),
    )
    .mockResolvedValueOnce(evidence('fixture-evidence-second', ''));
  render(
    <OverviewConnectionsPopover
      label="今日认证失败"
      scope="authenticationFailures"
    >
      今日认证失败
    </OverviewConnectionsPopover>,
  );
  const trigger = screen.getByRole('button', { name: '今日认证失败' });
  fireEvent.click(trigger);
  expect(await screen.findByText('fixture-user')).toBeInTheDocument();
  expect(await screen.findByText('fixture-password')).toBeInTheDocument();
  expect(getEvidence).toHaveBeenCalledExactlyOnceWith(
    'fixture-evidence-first',
    { signal: expect.any(AbortSignal) },
  );
  const firstSignal = getEvidence.mock.lastCall?.[1]?.signal as AbortSignal;

  fireEvent.click(screen.getByTitle('2'));
  expect(firstSignal.aborted).toBe(true);
  expect(screen.queryByText('fixture-password')).not.toBeInTheDocument();
  expect(getEvidence).toHaveBeenCalledTimes(1);
  await act(async () =>
    finishSecond(
      result(2, '192.0.2.2', {
        username: 'fixture-empty-user',
        credentialArtifactId: 'fixture-evidence-second',
        materialType: 'Plaintext',
      }),
    ),
  );

  expect(await screen.findByText('（空密码）')).toBeInTheDocument();
  const secondSignal = getEvidence.mock.lastCall?.[1]?.signal as AbortSignal;
  fireEvent.keyDown(screen.getByRole('dialog'), { key: 'Escape' });
  expect(secondSignal.aborted).toBe(true);
  expect(screen.queryByText('（空密码）')).not.toBeInTheDocument();
});

it.each([
  { canAdmin: false, materialType: 'Plaintext', fallback: '仅管理员可查看' },
  { canAdmin: true, materialType: 'Response', fallback: '未采集密码' },
])('认证失败明确说明 $fallback 并跳过原文请求', async ({
  canAdmin,
  materialType,
  fallback,
}) => {
  access.canAdmin = canAdmin;
  getConnections.mockResolvedValue(
    result(1, '192.0.2.1', {
      username: 'fixture-user',
      credentialArtifactId: 'fixture-evidence',
      materialType,
    }),
  );
  render(
    <OverviewConnectionsPopover
      label="今日认证失败"
      scope="authenticationFailures"
    >
      今日认证失败
    </OverviewConnectionsPopover>,
  );
  fireEvent.click(screen.getByRole('button', { name: '今日认证失败' }));
  expect(await screen.findByText('fixture-user')).toBeInTheDocument();
  expect(screen.getByText(fallback)).toBeInTheDocument();
  expect(getEvidence).not.toHaveBeenCalled();
});

it('点击协议来源数字，按协议和指标请求分页并显示每个 IP 的归属地', async () => {
  getConnections.mockResolvedValue(result(1, '192.0.2.1', { eventType: 'ProtocolViolation' }));
  const asOfUtc = '2026-11-15T01:30:00Z';
  render(<AdapterActivityCard loading={false} asOfUtc={asOfUtc} activity={[{
    adapterKey: 'redis',
    acceptedConnections: 0,
    authenticationFailures: 0,
    sourceIpCount: 6,
    protocolViolations: 1,
    lastActivityAtUtc: '2026-11-15T01:30:00Z',
  }]} />);
  expect(getConnections).not.toHaveBeenCalled();
  expect(screen.queryByRole('button', { name: 'REDIS 连接明细，0' })).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'REDIS 来源 IP 明细，6' }));
  const dialog = within(await screen.findByRole('dialog', { name: 'REDIS 来源 IP 明细' }));
  expect(await dialog.findByRole('cell', { name: '192.0.2.1' })).toBeInTheDocument();
  expect(await dialog.findByRole('cell', { name: '示例国家 · 示例城市' })).toBeInTheDocument();
  expect(dialog.getByRole('cell', { name: '协议异常' })).toBeInTheDocument();
  expect(getConnections).toHaveBeenLastCalledWith({
    scope: 'adapterActivity', adapterKey: 'redis', metric: 'sourceIpCount', asOfUtc, page: 1, pageSize: 5,
  });
});

it('协议认证失败明细使用相同证据权限', async () => {
  access.canAdmin = false;
  getConnections.mockResolvedValue(result(1, '192.0.2.1', {
    username: 'fixture-user', credentialArtifactId: 'fixture-evidence', materialType: 'Plaintext',
  }));
  render(<AdapterActivityCard loading={false} activity={[{
    adapterKey: 'redis',
    acceptedConnections: 1,
    authenticationFailures: 1,
    sourceIpCount: 1,
    protocolViolations: 0,
    lastActivityAtUtc: '2026-11-15T01:30:00Z',
  }]} />);
  fireEvent.click(screen.getByRole('button', { name: 'REDIS 认证失败明细，1' }));
  const dialog = within(await screen.findByRole('dialog', { name: 'REDIS 认证失败明细' }));
  expect(await dialog.findByText('fixture-user')).toBeInTheDocument();
  expect(dialog.getByText('仅管理员可查看')).toBeInTheDocument();
  expect(getEvidence).not.toHaveBeenCalled();
});
