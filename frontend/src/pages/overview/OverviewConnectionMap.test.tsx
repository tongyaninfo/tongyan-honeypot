import { HubConnectionState } from '@microsoft/signalr';
import {
  cleanup,
  fireEvent,
  render,
  screen,
  within,
} from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import type {
  ConnectionMapEvent,
  ConnectionMapSnapshot,
} from '@/services/honeypot/api';
import OverviewConnectionMap from './OverviewConnectionMap';

vi.mock('./connectionMapGeometry', async (importOriginal) => ({
  ...(await importOriginal<typeof import('./connectionMapGeometry')>()),
  loadWorldPath: vi.fn().mockResolvedValue('M0,0 L100,100 Z'),
}));

afterEach(cleanup);

function source(
  id: string,
  editor: Partial<ConnectionMapEvent> = {},
): ConnectionMapEvent {
  return {
    id,
    occurredAtUtc: '2026-11-15T02:00:00Z',
    adapterKey: 'ssh',
    latitude: 31,
    longitude: 121,
    locationLabel: '样例位置',
    ...editor,
  };
}

function renderMap(
  events: ConnectionMapEvent[],
  playback: {
    pause?: (value: boolean) => void;
    paused?: boolean;
    reducedMotion?: boolean;
    flightEvents?: ConnectionMapEvent[];
  } = {},
  aggregate: Partial<ConnectionMapSnapshot> = {},
) {
  const selectWindow = vi.fn();
  const snapshot: ConnectionMapSnapshot = {
    sampledAtUtc: '2026-11-15T02:00:01Z',
    windowSeconds: 600,
    target: { status: 'ready', latitude: 31, longitude: 121 },
    events,
    coverage: {
      observed: events.length,
      mapped: events.length,
      unknown: 0,
      private: 0,
      pending: 0,
      omitted: 0,
    },
    locationEnabled: true,
    ...aggregate,
  };
  render(
    <OverviewConnectionMap
      dark={false}
      windowSeconds={600}
      selectWindow={selectWindow}
      snapshot={snapshot}
      unavailable={false}
      flightEvents={playback.flightEvents ?? []}
      connectionState={HubConnectionState.Connected}
      paused={playback.paused ?? false}
      reducedMotion={playback.reducedMotion ?? false}
      pause={playback.pause ?? vi.fn()}
    />,
  );
  return selectWindow;
}

function scrollAt(
  map: Element,
  deltaY: number,
  clientX: number,
  clientY: number,
  ctrlKey = false,
) {
  // Happy DOM 的 WheelEvent 未包含鼠标坐标和修饰键，补齐浏览器的事件字段。
  return fireEvent(
    map,
    Object.assign(
      new WheelEvent('wheel', { deltaY, bubbles: true, cancelable: true }),
      { clientX, clientY, ctrlKey },
    ),
  );
}

it('悬停来源点时用原始地址和国家，重合位置合并 IP 且同一 IP 去重', async () => {
  renderMap([
    source('v4-no-country', { sourceIp: '192.0.2.10' }),
    source('v4-country', { sourceIp: '192.0.2.10', country: '测试国家' }),
    source('v6', { sourceIp: '2001:db8::21', country: '' }),
  ]);
  const origin = await screen.findByRole('button', {
    name: '样例位置 · SSH · 3 次连接',
  });
  expect(origin.querySelector('title')).toBeNull();
  fireEvent.mouseEnter(origin);
  const sources = await screen.findByRole('table', { name: '来源 IP 与国家' });
  expect(within(sources).getAllByRole('row')).toHaveLength(3);
  expect(
    within(sources).getByRole('row', { name: '192.0.2.10 测试国家' }),
  ).toBeInTheDocument();
  expect(
    within(sources).getByRole('row', { name: '2001:db8::21 未知' }),
  ).toBeInTheDocument();
});

it('来源汇总包含飞线样本以外的连接，并明确区分定位中和等待定位', async () => {
  renderMap(
    [],
    {},
    {
      origins: [
        {
          id: 'region-1',
          longitude: 121,
          latitude: 31,
          locationLabel: '区域汇总',
          adapterKey: 'ssh',
          connectionCount: 1700,
          sourceIpCount: 13,
          sources: [{ ip: '203.0.113.10', country: '样例国家' }],
        },
      ],
      adapterKeys: ['ssh', 'mssql'],
      coverage: {
        observed: 2000,
        mapped: 1700,
        pending: 250,
        deferred: 200,
        private: 25,
        unknown: 25,
        omitted: 1600,
      },
    },
  );
  const origin = await screen.findByRole('button', {
    name: '区域汇总 · 最近 SSH · 1,700 次连接',
  });
  expect(screen.getByText('已定位 1,700 / 观测 2,000')).toBeInTheDocument();
  expect(screen.getByText('定位中 50')).toBeInTheDocument();
  expect(screen.getByText('等待定位 200')).toBeInTheDocument();
  expect(screen.queryByText(/超出展示上限/)).toBeNull();
  expect(
    within(screen.getByRole('region', { name: '服务配色' })).getByText('MSSQL'),
  ).toBeInTheDocument();
  fireEvent.focus(origin);
  const sources = await screen.findByRole('table', { name: '来源 IP 与国家' });
  expect(
    within(sources).getByText('共 13 个来源 IP，显示最近 1 个'),
  ).toBeInTheDocument();
});

it('键盘聚焦时显示气泡，老版未返回地址时保留占位', async () => {
  renderMap([source('legacy')]);
  const origin = await screen.findByRole('button', {
    name: '样例位置 · SSH · 1 次连接',
  });
  expect(origin).toHaveAttribute('tabindex', '0');
  fireEvent.focus(origin);
  const sources = await screen.findByRole('table', { name: '来源 IP 与国家' });
  expect(
    within(sources).getByRole('row', { name: '— 未知' }),
  ).toBeInTheDocument();
});

it('时间下拉提供四档并提交所选窗口', async () => {
  const selectWindow = renderMap([]);
  expect(screen.getByText('10 分钟')).toBeInTheDocument();
  await screen.findByLabelText('最近 10 分钟连接来源分布');
  fireEvent.mouseDown(screen.getByRole('combobox', { name: '地图时间范围' }));
  const option = await screen.findByRole('option', { name: '24 小时' });
  expect(
    screen.getAllByRole('option').map((entry) => entry.textContent),
  ).toEqual(['60 秒', '10 分钟', '2 小时', '24 小时']);
  fireEvent.click(option);
  expect(selectWindow).toHaveBeenCalledWith(86400, expect.anything());
});

it('滚轮与触摸板手势围绕指针缩放地图，按住拖动并可复位', async () => {
  renderMap([source('zoom', { longitude: 0, latitude: 0 })]);
  const svg = await screen.findByLabelText('最近 10 分钟连接来源分布');
  const reset = screen.getByRole('button', { name: '复位地图' });
  expect(screen.queryByRole('button', { name: '放大地图' })).toBeNull();
  expect(screen.queryByRole('button', { name: '缩小地图' })).toBeNull();
  vi.spyOn(svg, 'getBoundingClientRect').mockReturnValue(
    new DOMRect(0, 0, 1000, 456),
  );
  const view = () => svg.getAttribute('viewBox')?.split(' ').map(Number) ?? [];
  expect(reset).toBeDisabled();
  fireEvent.pointerDown(svg, {
    pointerId: 1,
    isPrimary: true,
    button: 0,
    clientX: 40,
    clientY: 40,
  });
  fireEvent.pointerMove(svg, { pointerId: 1, clientX: 75, clientY: 55 });
  fireEvent.pointerUp(svg, { pointerId: 1 });
  expect(view()).toEqual([-35, -15, 1000, 456]);
  fireEvent.click(reset);

  const scroll = (deltaY: number, ctrlKey = false) =>
    scrollAt(svg, deltaY, 250, 114, ctrlKey);
  expect(scroll(-120)).toBe(false);
  const [x, y, width, height] = view();
  expect(width).toBeLessThan(1000);
  expect(x + width / 4).toBeCloseTo(250);
  expect(y + height / 4).toBeCloseTo(114);
  scroll(-5, true);
  expect(view()[2]).toBeLessThan(width);
  scroll(-1500);
  expect(view()[2]).toEqual(250);
  fireEvent.pointerDown(svg, {
    pointerId: 1,
    isPrimary: true,
    button: 0,
    clientX: 40,
    clientY: 40,
  });
  fireEvent.pointerMove(svg, { pointerId: 1, clientX: 2500, clientY: 2500 });
  fireEvent.pointerUp(svg, { pointerId: 1 });
  expect(svg).toHaveAttribute('viewBox', '0 0 250 114');
  scroll(120);
  expect(view()[2]).toBeGreaterThan(250);
  fireEvent.click(reset);
  expect(svg).toHaveAttribute('viewBox', '0 0 1000 456');
  expect(reset).toBeDisabled();
});

it('放大地图时来源和飞线点缩小，来源命中范围及落点不会随视野放大', async () => {
  renderMap(
    [source('center', { longitude: 0, latitude: 0, sourceIp: '192.0.2.10' })],
    { flightEvents: [source('in-flight', { longitude: 30, latitude: 15 })] },
    { target: { status: 'ready', longitude: 0, latitude: 0 } },
  );
  const marker = await screen.findByRole('button', {
    name: '样例位置 · SSH · 1 次连接',
  });
  const svg = await screen.findByLabelText('最近 10 分钟连接来源分布');
  const [hit, visible] = marker.querySelectorAll('circle');
  const motion = svg.querySelector('animateMotion');
  const movingPoint = motion?.parentElement;
  const target = svg.querySelector('g[pointer-events="none"]');
  const arrival = svg.querySelector('circle[transform]');
  vi.spyOn(svg, 'getBoundingClientRect').mockReturnValue(
    new DOMRect(0, 0, 1000, 456),
  );
  const path = motion?.getAttribute('path');
  const radius = (circle: Element | null | undefined) =>
    Number(circle?.getAttribute('r'));
  const [initialVisible, initialHit, initialMoving] = [
    radius(visible),
    radius(hit),
    radius(movingPoint),
  ];
  expect(initialVisible).toBeGreaterThan(0);
  expect(initialMoving).toBe(4);

  scrollAt(svg, -1500, 500, 228);

  expect(svg).toHaveAttribute('viewBox', '375 171 250 114');
  expect(radius(visible) * 4).toBeLessThan(initialVisible);
  expect(radius(hit) * 4).toBeCloseTo(initialHit);
  expect(radius(movingPoint) * 4).toBeLessThan(initialMoving);
  expect(target?.getAttribute('transform')).toMatch(/scale\(0\.25\)$/);
  expect(arrival?.getAttribute('transform')).toMatch(/scale\(0\.25\)$/);
  expect(motion).toHaveAttribute('path', path);

  fireEvent.focus(marker);
  expect(
    await screen.findByRole('row', { name: '192.0.2.10 未知' }),
  ).toBeInTheDocument();
});

it('左侧暂停飞线、右侧实时，默认开启且点击切换到暂停', () => {
  const pause = vi.fn();
  renderMap([], { pause });
  const toggle = screen.getByRole('switch', { name: '实时飞线' });
  expect(toggle).toBeChecked();
  expect(toggle.previousElementSibling).toHaveTextContent('暂停飞线');
  expect(toggle.nextElementSibling).toHaveTextContent('实时');
  fireEvent.click(toggle);
  expect(pause).toHaveBeenCalledWith(true);
});

it('浏览器未授予原生全屏权限时使用页面内全屏，Escape 可退出', async () => {
  renderMap([source('fullscreen')]);
  const svg = await screen.findByLabelText('最近 10 分钟连接来源分布');
  const fullscreen = screen.getByRole('button', { name: '全屏地图' });
  const shell = fullscreen.closest('.ant-card')?.parentElement;
  expect(shell).toBeDefined();
  if (!shell) throw new Error('Map fullscreen container unavailable');
  shell.requestFullscreen = vi
    .fn()
    .mockRejectedValue(new Error('Permission denied'));
  fireEvent.click(fullscreen);
  const region = screen.getByRole('region', { name: '全球连接地图' });
  expect(
    await within(region).findByRole('button', { name: '退出全屏' }),
  ).toBeInTheDocument();
  expect(region).toContainElement(svg);
  fireEvent.keyDown(document, { key: 'Escape' });
  expect(screen.getByRole('button', { name: '全屏地图' })).toBeInTheDocument();
});
