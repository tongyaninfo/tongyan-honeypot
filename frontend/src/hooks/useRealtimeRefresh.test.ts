import { HubConnectionState } from '@microsoft/signalr';
import { act, cleanup, renderHook } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { connectHoneypotRealtime } from '@/services/realtime';
import { useRealtimeRefresh } from './useRealtimeRefresh';

vi.mock('@/services/realtime', () => ({ connectHoneypotRealtime: vi.fn() }));

const connect = vi.mocked(connectHoneypotRealtime);

beforeEach(() => {
  vi.useFakeTimers();
  connect.mockResolvedValue(async () => {});
});

afterEach(() => {
  cleanup();
  connect.mockReset();
  vi.useRealTimers();
});

it('keeps the 750 ms realtime refresh for other pages', async () => {
  const refresh = vi.fn(async () => {});
  renderHook(() => useRealtimeRefresh(refresh));
  const handlers = connect.mock.calls[0][0];
  expect(refresh).not.toHaveBeenCalled();
  expect(handlers.onRuntime).toBeUndefined();

  handlers.onEvent?.();
  await act(async () => vi.advanceTimersByTimeAsync(749));
  expect(refresh).not.toHaveBeenCalled();
  await act(async () => vi.advanceTimersByTimeAsync(1));
  expect(refresh).toHaveBeenCalledTimes(1);
});

it('refreshes overview immediately on mount, coalesces later requests, and notifies map observers immediately', async () => {
  let finishInitial = () => {};
  const initial = new Promise<void>((resolve) => { finishInitial = resolve; });
  const refresh = vi.fn(async () => {}).mockReturnValueOnce(initial);
  const onConnectionAccepted = vi.fn();
  const onConnectionState = vi.fn();
  renderHook(() => useRealtimeRefresh(refresh, true, { onConnectionAccepted, onConnectionState }, {
    coalesceMs: 5_000,
    refreshOnMount: true,
  }));
  const handlers = connect.mock.calls[0][0];
  expect(refresh).toHaveBeenCalledTimes(1);

  const connection = { connectionId: 'fixture', occurredAtUtc: '2026-11-16T00:00:00Z' };
  handlers.onEvent?.();
  handlers.onRuntime?.();
  handlers.onConnectionAccepted?.(connection);
  handlers.onConnectionState?.(HubConnectionState.Connected);
  expect(onConnectionAccepted).toHaveBeenCalledWith(connection);
  expect(onConnectionState).toHaveBeenCalledWith(HubConnectionState.Connected);
  await act(async () => vi.advanceTimersByTimeAsync(6_000));
  expect(refresh).toHaveBeenCalledTimes(1);

  await act(async () => { finishInitial(); });
  handlers.onEvent?.();
  await act(async () => vi.advanceTimersByTimeAsync(4_999));
  expect(refresh).toHaveBeenCalledTimes(1);
  await act(async () => vi.advanceTimersByTimeAsync(1));
  expect(refresh).toHaveBeenCalledTimes(2);
  await act(async () => vi.advanceTimersByTimeAsync(5_000));
  expect(refresh).toHaveBeenCalledTimes(2);
});
