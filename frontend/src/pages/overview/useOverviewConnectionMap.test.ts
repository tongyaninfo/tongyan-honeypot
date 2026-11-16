import { HubConnectionState } from '@microsoft/signalr';
import { act, cleanup, renderHook } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import {
  type ApiResult,
  type ConnectionMapEvent,
  type ConnectionMapSnapshot,
  type ConnectionMapWindowSeconds,
  getOverviewConnectionMap,
} from '@/services/honeypot/api';
import { serviceColor } from './connectionMapGeometry';
import { useOverviewConnectionMap } from './useOverviewConnectionMap';

vi.mock('@/services/honeypot/api', () => ({
  getOverviewConnectionMap: vi.fn(),
}));

const getSnapshot = vi.mocked(getOverviewConnectionMap);
const start = Date.parse('2026-11-15T02:00:00Z');
let events: ConnectionMapEvent[];
let pending: number;

function event(id: string, offset = 50): ConnectionMapEvent {
  return {
    id,
    occurredAtUtc: new Date(start + offset).toISOString(),
    adapterKey: 'ssh',
    longitude: -74,
    latitude: 40,
    locationLabel: '合成来源',
  };
}

function advance(ms: number) {
  return act(async () => {
    await vi.advanceTimersByTimeAsync(ms);
  });
}

function response(
  windowSeconds: ConnectionMapWindowSeconds,
): ApiResult<ConnectionMapSnapshot> {
  return {
    success: true,
    code: 'OK',
    message: '',
    data: {
      sampledAtUtc: new Date().toISOString(),
      windowSeconds,
      target: { status: 'ready', latitude: 31, longitude: 121 },
      events,
      coverage: {
        observed: events.length + pending,
        mapped: events.length,
        pending,
        unknown: 0,
        private: 0,
        omitted: 0,
      },
      locationEnabled: true,
    },
  };
}

beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(start);
  vi.spyOn(document, 'hidden', 'get').mockReturnValue(false);
  events = [event('baseline', -100)];
  pending = 0;
  getSnapshot.mockImplementation(async (windowSeconds) =>
    response(windowSeconds),
  );
});

afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.restoreAllMocks();
  getSnapshot.mockReset();
});

it('首屏静态展示，飞线只消费已收到通知的新连接且按连接 ID 去重', async () => {
  const { result } = renderHook(useOverviewConnectionMap);
  act(() => result.current.onConnectionState(HubConnectionState.Connected));
  await advance(0);
  expect(result.current.snapshot?.events.map(({ id }) => id)).toEqual([
    'baseline',
  ]);
  expect(result.current.flightEvents).toEqual([]);

  const fresh = event('new');
  events = [...events, fresh, event('no-notice', 51)];
  act(() => {
    result.current.onConnectionAccepted({
      connectionId: 'baseline',
      occurredAtUtc: fresh.occurredAtUtc,
    });
    result.current.onConnectionAccepted({
      connectionId: fresh.id,
      occurredAtUtc: fresh.occurredAtUtc,
    });
    result.current.onConnectionAccepted({
      connectionId: fresh.id,
      occurredAtUtc: fresh.occurredAtUtc,
    });
  });
  await advance(520);
  expect(result.current.snapshot?.events).toHaveLength(3);
  expect(result.current.flightEvents.map(({ id }) => id)).toEqual(['new']);
  expect(getSnapshot).toHaveBeenCalledTimes(2);

  act(() => result.current.onConnectionState(HubConnectionState.Reconnecting));
  expect(result.current.flightEvents).toEqual([]);
  events = [...events, event('during-outage', 600)];
  act(() => result.current.onConnectionState(HubConnectionState.Connected));
  await advance(0);
  expect(result.current.snapshot?.events).toHaveLength(4);
  expect(result.current.flightEvents).toEqual([]);
});

it('待解析连接按短间隔补查，暂停后仍更新静态数据且恢复不补播', async () => {
  const { result } = renderHook(useOverviewConnectionMap);
  act(() => result.current.onConnectionState(HubConnectionState.Connected));
  await advance(0);
  const fresh = event('wait-location');
  pending = 1;
  act(() =>
    result.current.onConnectionAccepted({
      connectionId: fresh.id,
      occurredAtUtc: fresh.occurredAtUtc,
    }),
  );
  await advance(400);
  expect(result.current.snapshot?.coverage.pending).toBe(1);
  expect(result.current.flightEvents).toEqual([]);

  pending = 0;
  events = [...events, fresh];
  await advance(1620);
  expect(result.current.flightEvents.map(({ id }) => id)).toEqual([fresh.id]);
  act(() => result.current.pause(true));
  expect(result.current.flightEvents).toEqual([]);
  const paused = event('during-pause', 3000);
  events = [...events, paused];
  act(() =>
    result.current.onConnectionAccepted({
      connectionId: paused.id,
      occurredAtUtc: paused.occurredAtUtc,
    }),
  );
  await advance(520);
  expect(result.current.snapshot?.events).toHaveLength(3);
  expect(result.current.flightEvents).toEqual([]);
  act(() => result.current.pause(false));
  await advance(5100);
  expect(result.current.flightEvents).toEqual([]);
});

it('突发连接最多同屏播放 32 条，内置服务配色独立', async () => {
  const { result } = renderHook(useOverviewConnectionMap);
  act(() => result.current.onConnectionState(HubConnectionState.Connected));
  await advance(0);
  events = Array.from({ length: 230 }, (_, index) => event(`burst-${index}`));
  act(() => {
    for (const item of events)
      result.current.onConnectionAccepted({
        connectionId: item.id,
        occurredAtUtc: item.occurredAtUtc,
      });
  });
  await advance(400 + 120 * 8);
  expect(result.current.flightEvents).toHaveLength(32);
  expect(serviceColor('mongodb', false)).not.toBe(serviceColor('ssh', false));
  expect(serviceColor('mongodb', true)).not.toBe(serviceColor('unknown', true));
});

it('页面隐藏时停止取数，恢复可见后只补来源不播放旧飞线', async () => {
  let hidden = false;
  vi.spyOn(document, 'hidden', 'get').mockImplementation(() => hidden);
  const { result } = renderHook(useOverviewConnectionMap);
  act(() => result.current.onConnectionState(HubConnectionState.Connected));
  await advance(0);
  hidden = true;
  act(() => document.dispatchEvent(new Event('visibilitychange')));
  const item = event('while-hidden');
  events = [...events, item];
  act(() =>
    result.current.onConnectionAccepted({
      connectionId: item.id,
      occurredAtUtc: item.occurredAtUtc,
    }),
  );
  await advance(6000);
  expect(getSnapshot).toHaveBeenCalledTimes(1);

  hidden = false;
  act(() => document.dispatchEvent(new Event('visibilitychange')));
  await advance(0);
  expect(result.current.snapshot?.events).toHaveLength(2);
  expect(result.current.flightEvents).toEqual([]);
});

it('默认查询十分钟，切换范围取消旧请求并建立静态基线，新实时事件仍播放', async () => {
  const { result } = renderHook(useOverviewConnectionMap);
  act(() => result.current.onConnectionState(HubConnectionState.Connected));
  await advance(0);
  expect(result.current.windowSeconds).toBe(600);
  expect(getSnapshot).toHaveBeenCalledWith(600, expect.any(AbortSignal));

  let oldSignal: AbortSignal | undefined;
  let finishOldRequest: (data: ApiResult<ConnectionMapSnapshot>) => void =
    () => {};
  getSnapshot.mockImplementationOnce((_windowSeconds, signal) => {
    oldSignal = signal;
    return new Promise((resolve) => {
      finishOldRequest = resolve;
    });
  });
  const oldNotice = event('old-window-notice');
  act(() =>
    result.current.onConnectionAccepted({
      connectionId: oldNotice.id,
      occurredAtUtc: oldNotice.occurredAtUtc,
    }),
  );
  await advance(400);

  events = [event('historical', -700000), oldNotice];
  act(() => result.current.selectWindow(7200));
  expect(oldSignal?.aborted).toBe(true);
  expect(result.current.snapshot).toBeUndefined();
  await advance(0);
  expect(getSnapshot).toHaveBeenLastCalledWith(7200, expect.any(AbortSignal));
  expect(result.current.snapshot?.events.map(({ id }) => id)).toEqual([
    'historical',
    oldNotice.id,
  ]);
  expect(result.current.flightEvents).toEqual([]);

  await act(async () => finishOldRequest(response(600)));
  expect(result.current.snapshot?.windowSeconds).toBe(7200);
  const fresh = event('after-window-change', 500);
  events = [...events, fresh];
  act(() =>
    result.current.onConnectionAccepted({
      connectionId: fresh.id,
      occurredAtUtc: fresh.occurredAtUtc,
    }),
  );
  await advance(520);
  expect(result.current.flightEvents.map(({ id }) => id)).toEqual([fresh.id]);
});
