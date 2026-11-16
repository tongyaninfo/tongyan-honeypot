import { HubConnectionState } from '@microsoft/signalr';
import { useCallback, useEffect, useRef, useState } from 'react';
import {
  type ConnectionMapEvent,
  type ConnectionMapSnapshot,
  type ConnectionMapWindowSeconds,
  getOverviewConnectionMap,
} from '@/services/honeypot/api';
import type { HoneypotRealtimeHandlers } from '@/services/realtime';
import { coordinates } from './connectionMapGeometry';

const mergeDelay = 400;
const refreshInterval = 5000;
const pendingRefreshInterval = 1500;
const noticeLifetime = 10000;
const maxQueued = 200;
const maxFlights = 32;
const maxSeen = 800;
const defaultWindowSeconds: ConnectionMapWindowSeconds = 600;
export const flightDuration = 2000;
export const arrivalDuration = 550;

type MapControls = Required<
  Pick<HoneypotRealtimeHandlers, 'onConnectionAccepted' | 'onConnectionState'>
> & {
  pause: (paused: boolean) => void;
  selectWindow: (window: ConnectionMapWindowSeconds) => void;
};

type QueuedFlight = { event: ConnectionMapEvent; receivedAt: number };
type ActiveFlight = { event: ConnectionMapEvent; expiresAt: number };

export function useOverviewConnectionMap() {
  const controls = useRef<MapControls>(null);
  const [windowSeconds, setWindowSeconds] = useState(defaultWindowSeconds);
  const [snapshot, setSnapshot] = useState<ConnectionMapSnapshot>();
  const [unavailable, setUnavailable] = useState(false);
  const [flightEvents, setFlightEvents] = useState<ConnectionMapEvent[]>([]);
  const [connectionState, setConnectionState] = useState(
    HubConnectionState.Connecting,
  );
  const [paused, setPaused] = useState(false);
  const [reducedMotion, setReducedMotion] = useState(false);

  const onConnectionAccepted = useCallback<MapControls['onConnectionAccepted']>(
    (event) => controls.current?.onConnectionAccepted(event),
    [],
  );
  const onConnectionState = useCallback<MapControls['onConnectionState']>(
    (state) => controls.current?.onConnectionState(state),
    [],
  );
  const pause = useCallback((value: boolean) => {
    setPaused(value);
    controls.current?.pause(value);
  }, []);
  const selectWindow = useCallback<MapControls['selectWindow']>(
    (value) => controls.current?.selectWindow(value),
    [],
  );

  useEffect(() => {
    let disposed = false;
    let request: AbortController | undefined;
    let refreshTimer: ReturnType<typeof setTimeout> | undefined;
    let refreshDueAt: number | undefined;
    let flightTimer: ReturnType<typeof setTimeout> | undefined;
    let refreshPending = false;
    let hubState = HubConnectionState.Connecting;
    let baselineTime: number | undefined;
    let motionPaused = false;
    let requestedWindow = defaultWindowSeconds;
    let active: ActiveFlight[] = [];
    const queued: QueuedFlight[] = [];
    const pendingIds = new Map<string, number>();
    const seenIds = new Set<string>();
    const media = window.matchMedia('(prefers-reduced-motion: reduce)');
    setReducedMotion(media.matches);

    const canPlay = () =>
      hubState === HubConnectionState.Connected &&
      !document.hidden &&
      !motionPaused &&
      !media.matches;

    function clearFlights() {
      clearTimeout(flightTimer);
      flightTimer = undefined;
      queued.length = 0;
      active = [];
      setFlightEvents((previous) => (previous.length ? [] : previous));
    }

    function resetBaseline() {
      baselineTime = undefined;
      pendingIds.clear();
      seenIds.clear();
      clearFlights();
    }

    function scheduleFlightTick() {
      if (flightTimer === undefined)
        flightTimer = setTimeout(advanceFlights, 120);
    }

    function advanceFlights() {
      flightTimer = undefined;
      if (disposed || !canPlay()) return;
      const now = Date.now();
      const previousCount = active.length;
      active = active.filter((item) => item.expiresAt > now);
      let changed = active.length !== previousCount;
      // 分批播放，突发流量下也不会同一帧启动大量动画。
      for (let count = 0; count < 6 && active.length < maxFlights; count++) {
        const item = queued.shift();
        if (!item) break;
        if (now - item.receivedAt > noticeLifetime) continue;
        active.push({
          event: item.event,
          expiresAt: now + flightDuration + arrivalDuration,
        });
        changed = true;
      }
      if (changed) setFlightEvents(active.map((item) => item.event));
      if (queued.length || active.length) scheduleFlightTick();
    }

    function applySnapshot(data: ConnectionMapSnapshot, sampledAt: number) {
      const now = Date.now();
      if (baselineTime === undefined) baselineTime = sampledAt;
      const targetReady =
        data.target.status === 'ready' && coordinates(data.target) !== null;
      if (!targetReady) clearFlights();
      for (const [id, receivedAt] of pendingIds) {
        if (now - receivedAt > noticeLifetime) pendingIds.delete(id);
      }
      for (const event of data.events) {
        if (seenIds.has(event.id)) continue;
        const receivedAt = pendingIds.get(event.id);
        // 已经收到实时通知的事件先等坐标。首屏和重连快照只建立来源基线。
        if (receivedAt !== undefined && canPlay() && !targetReady) continue;
        if (
          receivedAt !== undefined &&
          canPlay() &&
          coordinates(event) &&
          queued.length < maxQueued
        ) {
          queued.push({ event, receivedAt });
        }
        pendingIds.delete(event.id);
        seenIds.add(event.id);
        if (seenIds.size > maxSeen) {
          const oldest = seenIds.values().next().value;
          if (oldest !== undefined) seenIds.delete(oldest);
        }
      }
      if (queued.length) scheduleFlightTick();
      setSnapshot(data);
      setUnavailable(false);
    }

    function scheduleRefresh(delay = mergeDelay) {
      if (disposed || document.hidden) return;
      if (request) {
        refreshPending = true;
        return;
      }
      const dueAt = Date.now() + delay;
      if (refreshDueAt !== undefined && refreshDueAt <= dueAt) return;
      clearTimeout(refreshTimer);
      refreshDueAt = dueAt;
      refreshTimer = setTimeout(() => void refresh(), delay);
    }

    async function refresh() {
      refreshTimer = undefined;
      refreshDueAt = undefined;
      if (disposed || document.hidden) return;
      const controller = new AbortController();
      request = controller;
      const selectedWindow = requestedWindow;
      let interval = refreshInterval;
      try {
        const { success, data } = await getOverviewConnectionMap(
          selectedWindow,
          controller.signal,
        );
        if (controller.signal.aborted) return;
        const sampledAt = Date.parse(data?.sampledAtUtc ?? '');
        if (
          !success ||
          !Array.isArray(data?.events) ||
          data.windowSeconds !== selectedWindow ||
          !Number.isFinite(sampledAt)
        )
          throw new Error('Map snapshot unavailable');
        applySnapshot(data, sampledAt);
        if (
          data.target.status === 'pending' ||
          data.coverage.pending > (data.coverage.deferred ?? 0) ||
          pendingIds.size > 0
        )
          interval = pendingRefreshInterval;
      } catch {
        if (!controller.signal.aborted) {
          resetBaseline();
          setSnapshot(undefined);
          setUnavailable(true);
        }
      } finally {
        if (request === controller) {
          request = undefined;
          const delay = refreshPending ? mergeDelay : interval;
          refreshPending = false;
          scheduleRefresh(delay);
        }
      }
    }

    function restartSnapshot() {
      resetBaseline();
      request?.abort();
      request = undefined;
      clearTimeout(refreshTimer);
      refreshTimer = undefined;
      refreshDueAt = undefined;
      refreshPending = false;
      scheduleRefresh(0);
    }

    function onMotionChange() {
      setReducedMotion(media.matches);
      pendingIds.clear();
      clearFlights();
    }

    controls.current = {
      onConnectionAccepted: ({ connectionId, occurredAtUtc }) => {
        scheduleRefresh();
        if (
          !canPlay() ||
          baselineTime === undefined ||
          pendingIds.has(connectionId) ||
          seenIds.has(connectionId)
        )
          return;
        const occurredAt = Date.parse(occurredAtUtc);
        if (!Number.isFinite(occurredAt) || occurredAt <= baselineTime) return;
        if (pendingIds.size + queued.length < maxQueued)
          pendingIds.set(connectionId, Date.now());
      },
      onConnectionState: (state) => {
        if (hubState === state) return;
        hubState = state;
        setConnectionState(state);
        restartSnapshot();
      },
      pause: (value) => {
        motionPaused = value;
        pendingIds.clear();
        clearFlights();
      },
      selectWindow: (value) => {
        if (value === requestedWindow) return;
        requestedWindow = value;
        setWindowSeconds(value);
        setSnapshot(undefined);
        setUnavailable(false);
        // 新窗口首个快照只更新静态来源，不补播时间范围内的历史连接。
        restartSnapshot();
      },
    };

    media.addEventListener('change', onMotionChange);
    document.addEventListener('visibilitychange', restartSnapshot);
    scheduleRefresh(0);
    return () => {
      disposed = true;
      controls.current = null;
      request?.abort();
      clearTimeout(refreshTimer);
      clearTimeout(flightTimer);
      media.removeEventListener('change', onMotionChange);
      document.removeEventListener('visibilitychange', restartSnapshot);
    };
  }, []);

  return {
    windowSeconds,
    selectWindow,
    snapshot,
    unavailable,
    flightEvents,
    connectionState,
    paused,
    reducedMotion,
    pause,
    onConnectionAccepted,
    onConnectionState,
  };
}
