import type { LineConfig } from '@ant-design/plots';
import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import type { ActivityHour } from '@/services/honeypot/api';
import OverviewActivityTrend from './OverviewActivityTrend';

const draw = vi.hoisted(() => vi.fn());
vi.mock('@ant-design/plots', () => ({
  Line: (props: LineConfig) => {
    draw(props);
    return <div data-testid="overview-trend" />;
  },
}));

beforeEach(() => {
  vi.spyOn(HTMLElement.prototype, 'getBoundingClientRect').mockReturnValue(new DOMRect(0, 0, 600, 202));
  vi.stubGlobal('ResizeObserver', class {
    observe() {}
    disconnect() {}
  });
});

afterEach(() => {
  cleanup();
  draw.mockClear();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

const unknownHour: ActivityHour = {
  key: '2026-11-14T15:00:00Z',
  acceptedConnections: null,
  authenticationFailures: null,
  coverageStatus: 'unknown',
};

it('区分接口不可用和没有可用观测', () => {
  const { rerender } = render(<OverviewActivityTrend loading={false} />);
  expect(screen.getByText('趋势数据不可用')).toBeInTheDocument();

  rerender(<OverviewActivityTrend hours={[unknownHour]} loading={false} />);
  expect(screen.getByText('近 24 小时暂无可用观测')).toBeInTheDocument();
  expect(draw).not.toHaveBeenCalled();
});

it('把有覆盖且计数为零的小时画出来', () => {
  const quietHour = { ...unknownHour, acceptedConnections: 0, authenticationFailures: 0, coverageStatus: 'complete' } as const;
  render(<OverviewActivityTrend hours={[quietHour]} loading={false} />);

  expect(screen.getByTestId('overview-trend')).toBeInTheDocument();
  expect(draw).toHaveBeenLastCalledWith(expect.objectContaining({
    data: [
      expect.objectContaining({ series: '连接', count: 0 }),
      expect.objectContaining({ series: '认证失败', count: 0 }),
    ],
  }));
});

it('保留未知小时的空值，绘制孤立的观测点并用北京时间标注横轴', () => {
  const observedHour: ActivityHour = {
    key: '2026-11-14T16:00:00Z', acceptedConnections: 4,
    authenticationFailures: 0, coverageStatus: 'partial',
  };
  const hours = [unknownHour, observedHour, { ...unknownHour, key: '2026-11-14T17:00:00Z' }];
  render(<OverviewActivityTrend hours={hours} loading={false} />);

  expect(screen.getByText('部分小时采集覆盖不完整。曲线空白处没有可用观测。')).toBeInTheDocument();
  const chart = draw.mock.lastCall?.[0];
  expect(chart.connectNulls).toBe(false);
  expect(chart.scale.x.domain).toEqual(hours.map((item) => item.key));
  expect(chart.axis.x.labelFormatter(observedHour.key)).toBe('00:00');
  expect(chart.data.map((item: { count: number | null }) => item.count)).toEqual([null, null, 4, 0, null, null]);
  expect(chart.point.data).toEqual([
    expect.objectContaining({ hour: observedHour.key, series: '连接', count: 4 }),
    expect.objectContaining({ hour: observedHour.key, series: '认证失败', count: 0 }),
  ]);
});

it('为悬停小时启用横纵准线，并显示两个指标及其采集覆盖', () => {
  const observedHour: ActivityHour = {
    key: '2026-11-14T16:00:00Z', acceptedConnections: 4,
    authenticationFailures: 0, coverageStatus: 'partial',
  };
  render(<OverviewActivityTrend hours={[unknownHour, observedHour]} loading={false} />);

  const chart = draw.mock.lastCall?.[0];
  expect(chart.interaction.tooltip).toMatchObject({ shared: true, crosshairsX: true, crosshairsY: true });
  expect(chart.point.tooltip).toBe(false);
  const observed = chart.point.data[0];
  expect(chart.tooltip.title(observed)).toContain('00:00');
  expect(chart.tooltip.items.map((item: (datum: unknown) => unknown) => item(observed))).toMatchObject([
    { name: '连接', value: 4 },
    { name: '认证失败', value: 0 },
    { name: '采集覆盖', value: '采集覆盖不完整' },
  ]);
  expect(chart.tooltip.items.map((item: (datum: unknown) => unknown) => item(chart.data[0]))).toMatchObject([
    { name: '连接', value: '无可用观测' },
    { name: '认证失败', value: '无可用观测' },
    { name: '采集覆盖', value: '采集覆盖未知' },
  ]);
});
