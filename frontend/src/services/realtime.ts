import {
  HubConnectionBuilder,
  HubConnectionState,
  LogLevel,
  type HubConnection,
} from '@microsoft/signalr';
import type { ApiResult, InteractionEvent } from './honeypot/api';
import { getAccessToken } from './identity';
import { reportFrontendDiagnostic } from './frontendDiagnostics';

export type AcceptedConnectionNotice = Pick<InteractionEvent, 'connectionId' | 'occurredAtUtc'>;

export interface HoneypotRealtimeHandlers {
  onEvent?: () => void;
  onRuntime?: () => void;
  onConnectionState?: (state: HubConnectionState) => void;
  onConnectionAccepted?: (event: AcceptedConnectionNotice) => void;
}

/**
 * 创建管理台实时连接。token 始终从当前 sessionStorage 会话读取，
 * SignalR 只在 /hubs/honeypot 握手时把它作为 access_token 使用。
 */
export function createHoneypotRealtimeConnection(): HubConnection {
  const configuredBaseUrl = process.env.HONEYPOT_API_BASE_URL?.replace(/\/$/, '');
  const hubUrl = configuredBaseUrl
    ? `${configuredBaseUrl}/hubs/honeypot`
    : typeof window === 'undefined'
      ? '/hubs/honeypot'
      : `${window.location.origin}/hubs/honeypot`;
  return new HubConnectionBuilder()
    .withUrl(hubUrl, {
      accessTokenFactory: () => getAccessToken() ?? '',
    })
    // 短暂断网自动恢复；恢复后页面会重新拉取 REST 快照，不依赖消息补偿。
    .withAutomaticReconnect([0, 1000, 3000, 10000])
    .configureLogging(LogLevel.Warning)
    .build();
}

export async function connectHoneypotRealtime(
  handlers: HoneypotRealtimeHandlers,
): Promise<() => Promise<void>> {
  const connection = createHoneypotRealtimeConnection();
  const notify = (callback: (() => void) | undefined) => {
    callback?.();
  };

  connection.on('eventAppended', (message?: ApiResult<InteractionEvent>) => {
    notify(handlers.onEvent);
    const event = message?.success ? message.data : undefined;
    if (event?.eventType === 'ConnectionAccepted' &&
        typeof event.connectionId === 'string' && typeof event.occurredAtUtc === 'string') {
      handlers.onConnectionAccepted?.({ connectionId: event.connectionId, occurredAtUtc: event.occurredAtUtc });
    }
  });
  connection.on('runtimeChanged', () => notify(handlers.onRuntime));
  let stopping = false;
  connection.onreconnecting(() => {
    reportFrontendDiagnostic('UI_REALTIME_INTERRUPTED');
    handlers.onConnectionState?.(connection.state);
  });
  connection.onreconnected(() => {
    reportFrontendDiagnostic('UI_REALTIME_RECOVERED');
    handlers.onConnectionState?.(connection.state);
    // 重连后补取一次快照，防止断线期间遗漏状态变化。
    notify(handlers.onEvent);
    notify(handlers.onRuntime);
  });
  connection.onclose(() => {
    if (!stopping) reportFrontendDiagnostic('UI_REALTIME_INTERRUPTED');
    handlers.onConnectionState?.(connection.state);
  });

  try { await connection.start(); }
  catch (error) {
    reportFrontendDiagnostic('UI_REALTIME_INTERRUPTED');
    handlers.onConnectionState?.(HubConnectionState.Disconnected);
    throw error;
  }
  handlers.onConnectionState?.(connection.state);

  return async () => {
    stopping = true;
    connection.off('eventAppended');
    connection.off('runtimeChanged');
    if (connection.state !== HubConnectionState.Disconnected) {
      await connection.stop();
    }
  };
}
