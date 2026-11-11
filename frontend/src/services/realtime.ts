import {
  HubConnectionBuilder,
  HubConnectionState,
  LogLevel,
  type HubConnection,
} from '@microsoft/signalr';
import { getAccessToken } from './identity';
import { reportFrontendDiagnostic } from './frontendDiagnostics';

export interface HoneypotRealtimeHandlers {
  onEvent?: () => void;
  onRuntime?: () => void;
  onConnectionState?: (state: HubConnectionState) => void;
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

  connection.on('eventAppended', () => notify(handlers.onEvent));
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
  catch (error) { reportFrontendDiagnostic('UI_REALTIME_INTERRUPTED'); throw error; }
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
