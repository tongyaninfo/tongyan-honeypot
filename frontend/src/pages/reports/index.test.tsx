import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import * as api from '@/services/honeypot/reports';
import ReportsPage, { ResponsiveTrendLine } from './index';

const access = vi.hoisted(() => ({ canAdmin: true }));
vi.mock('@umijs/max', () => ({ request: vi.fn(), useAccess: () => access, useModel: () => ({ initialState: {} }), Link: ({ to, children }: { to: string; children: React.ReactNode }) => <a href={to}>{children}</a> }));
vi.mock('@ant-design/plots', () => ({ Line: ({ width }: { width?: number }) => <div data-testid="trend-plot" style={{ width }}>趋势图</div>, ConfigProvider: ({ children }: { children: React.ReactNode }) => children }));
vi.mock('@/services/honeypot/reports', async (original) => ({ ...await original<typeof api>(), getOperationReport: vi.fn(), getReportHistory: vi.fn(), getReportHistoryDetails: vi.fn(), sendOperationReport: vi.fn() }));
const totals: api.ReportTotals = { eventCount: null, acceptedConnections: null, uniqueSourceIps: null, newSourceIps: null, authenticationAttempts: null, authenticationFailures: null, protocolViolations: null, evidenceCount: null, truncatedEvents: null, sessionClosed: null };
const report: api.OperationReport = {
  generatedAtUtc: '2026-11-10T04:00:00Z', period: { kind: 'day', timeZone: 'Asia/Shanghai', startAtUtc: '2026-11-09T16:00:00Z', endAtUtc: '2026-11-10T04:00:00Z', granularity: 'hour', isCurrentPeriod: true },
  coverage: { status: 'unknown', coveredSeconds: 0, unknownSeconds: 43200, coveragePercent: 0, persistenceFailures: 0, hasObservedEvents: false }, totals,
  comparison: { startAtUtc: '2026-11-08T16:00:00Z', endAtUtc: '2026-11-09T04:00:00Z', coverageStatus: 'unknown', totals, connectionChangePercent: null, sourceIpChangePercent: null, authenticationFailureChangePercent: null },
  trend: [], protocols: [], ports: [], sources: [], regions: [], usernames: [], authenticationMethods: [], riskSignals: [], evidence: [], notes: ['未知时段不计作零事件。'],
  runtime: { sampleCount: 0, averageProcessCpuPercent: null, peakProcessCpuPercent: null, averageProcessMemoryBytes: null, peakProcessMemoryBytes: null, peakActiveConnections: null, averageRunningListeners: null, peakFailedListeners: null, lastConfiguredListeners: null, allListenersRunningPercent: null, lastDataDiskFreeBytes: null, minimumDataDiskFreeBytes: null },
};
const ok = <T,>(data: T) => ({ success: true, code: 'OK', message: '', data });
beforeEach(() => { vi.clearAllMocks(); access.canAdmin = true; vi.mocked(api.getOperationReport).mockResolvedValue(ok(report)); vi.mocked(api.getReportHistory).mockResolvedValue(ok({ items: [], total: 0, page: 1, pageSize: 10 })); });
afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.unstubAllGlobals(); });

it('redraws the trend at its parent width after initial layout shrinks without a window resize', () => {
  let resize: ResizeObserverCallback | undefined;
  const disconnect = vi.fn();
  vi.stubGlobal('ResizeObserver', class {
    constructor(callback: ResizeObserverCallback) { resize = callback; }
    observe() {}
    disconnect = disconnect;
  });
  const { unmount } = render(<ResponsiveTrendLine data={[]} />);
  const measure = (width: number) => act(() => resize?.([{ contentRect: { width } } as ResizeObserverEntry], {} as ResizeObserver));
  measure(991);
  expect(screen.getByTestId('trend-plot')).toHaveStyle({ width: '991px' });
  measure(894);
  expect(screen.getByTestId('trend-plot')).toHaveStyle({ width: '894px' });
  measure(260);
  expect(screen.getByTestId('trend-plot')).toHaveStyle({ width: '260px' });
  unmount();
  expect(disconnect).toHaveBeenCalledOnce();
});

it('shows missing observations as unavailable and requests the selected natural period', async () => {
  render(<ReportsPage />);
  await screen.findByText('暂无可用观测，不能推断本期没有活动');
  expect(screen.getAllByText('暂不可用').length).toBeGreaterThan(5);
  expect(screen.getByText('采集覆盖 0.0%，以下数值仅代表已记录数据')).toBeInTheDocument();
  fireEvent.click(screen.getByText('本周'));
  await waitFor(() => expect(api.getOperationReport).toHaveBeenCalledWith({ period: 'week' }, expect.any(AbortSignal)));
});

it.each([{ period: 'day', label: '今日' }, { period: 'week', label: '本周' }, { period: 'month', label: '本月' }])('keeps the natural $period request when generating and sending the latest report', async ({ period, label }) => {
  vi.mocked(api.sendOperationReport).mockResolvedValue(ok({ deliveryIds: ['report-mail-1'], message: 'queued' }));
  render(<ReportsPage />);
  await waitFor(() => expect(screen.getByRole('button', { name: '生成并发送最新报告' })).toBeEnabled());
  fireEvent.click(screen.getByText(label));
  await waitFor(() => expect(api.getOperationReport).toHaveBeenLastCalledWith({ period }, expect.any(AbortSignal)));
  await waitFor(() => expect(screen.getByRole('button', { name: '生成并发送最新报告' })).toBeEnabled());
  fireEvent.click(screen.getByRole('button', { name: '生成并发送最新报告' }));
  fireEvent.change(await screen.findByLabelText('收件人'), { target: { value: 'security@example.test' } });
  fireEvent.click(screen.getByRole('button', { name: '加入发送队列' }));
  await screen.findByText('报告邮件已加入发送队列，请到邮件记录查看结果。');
  expect(api.sendOperationReport).toHaveBeenCalledWith({ period, recipients: ['security@example.test'] });
  expect(screen.getByRole('link', { name: '查看邮件记录' })).toHaveAttribute('href', '/system/mail-records?status=all&id=report-mail-1');
});

it('allows analysts to read current reports without requesting admin history or showing send actions', async () => {
  access.canAdmin = false;
  render(<ReportsPage />);
  await screen.findByText('暂无可用观测，不能推断本期没有活动');
  expect(api.getOperationReport).toHaveBeenCalled();
  expect(api.getReportHistory).not.toHaveBeenCalled();
  expect(screen.queryByText('已生成报告')).not.toBeInTheDocument();
  expect(screen.queryByRole('button', { name: '生成并发送最新报告' })).not.toBeInTheDocument();
});

it('queries through today without a future endpoint and sends the same custom boundary later', async () => {
  const now = Date.parse('2026-11-10T04:00:00Z');
  vi.spyOn(Date, 'now').mockReturnValue(now);
  vi.mocked(api.sendOperationReport).mockResolvedValue(ok({ deliveryIds: ['custom-mail-1'], message: 'queued' }));
  render(<ReportsPage />);
  await screen.findByText('暂无可用观测，不能推断本期没有活动');
  fireEvent.click(screen.getByText('自定义'));
  expect(screen.getByLabelText('结束日期')).toHaveAttribute('max', '2026-11-10');
  fireEvent.change(screen.getByLabelText('开始日期'), { target: { value: '2026-11-09' } });
  fireEvent.change(screen.getByLabelText('结束日期'), { target: { value: '2026-11-10' } });
  fireEvent.click(screen.getByRole('button', { name: '查询区间' }));
  const query = { period: 'custom', startAtUtc: '2026-11-08T16:00:00.000Z', endAtUtc: '2026-11-10T04:00:00.000Z' };
  await waitFor(() => expect(api.getOperationReport).toHaveBeenLastCalledWith(query, expect.any(AbortSignal)));
  await waitFor(() => expect(screen.getByRole('button', { name: '发送当前区间报告' })).toBeEnabled());
  vi.mocked(Date.now).mockReturnValue(now + 60_000);
  fireEvent.click(screen.getByRole('button', { name: '发送当前区间报告' }));
  fireEvent.change(await screen.findByLabelText('收件人'), { target: { value: 'security@example.test' } });
  fireEvent.click(screen.getByRole('button', { name: '加入发送队列' }));
  await waitFor(() => expect(api.sendOperationReport).toHaveBeenCalledWith({ ...query, recipients: ['security@example.test'] }));
});
