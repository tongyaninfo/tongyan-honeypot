import { useEffect, useRef } from 'react';
import { connectHoneypotRealtime, type HoneypotRealtimeHandlers } from '@/services/realtime';

type RealtimeObservers = Pick<HoneypotRealtimeHandlers, 'onConnectionAccepted' | 'onConnectionState'>;

interface RealtimeRefreshOptions {
  coalesceMs?: number;
  refreshOnMount?: boolean;
}

/** 合并瞬间到达的事件。请求未完成时最多保留一次待刷新标记。 */
export function useRealtimeRefresh(
  refresh: () => Promise<void>,
  includeRuntime = false,
  observers?: RealtimeObservers,
  { coalesceMs = 750, refreshOnMount = false }: RealtimeRefreshOptions = {},
) {
  const currentRefresh = useRef(refresh);
  currentRefresh.current = refresh;
  const currentObservers = useRef(observers);
  currentObservers.current = observers;

  useEffect(() => {
    let active = true;
    let running = false;
    let pending = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let cleanup: (() => Promise<void>) | undefined;

    const run = () => {
      pending = false;
      running = true;
      void currentRefresh.current().finally(() => {
        running = false;
        if (pending) schedule();
      });
    };

    const schedule = () => {
      if (!active) return;
      pending = true;
      if (running || timer !== undefined) return;
      timer = setTimeout(() => {
        timer = undefined;
        run();
      }, coalesceMs);
    };

    if (refreshOnMount) run();
    void connectHoneypotRealtime({
      onEvent: schedule,
      onRuntime: includeRuntime ? schedule : undefined,
      onConnectionAccepted: (event) => { if (active) currentObservers.current?.onConnectionAccepted?.(event); },
      onConnectionState: (state) => { if (active) currentObservers.current?.onConnectionState?.(state); },
    })
      .then((dispose) => { if (active) cleanup = dispose; else void dispose(); })
      .catch(() => { /* 实时通道不可用时由页面保留 REST 快照。 */ });

    return () => {
      active = false;
      clearTimeout(timer);
      void cleanup?.();
    };
  }, [coalesceMs, includeRuntime, refreshOnMount]);
}
