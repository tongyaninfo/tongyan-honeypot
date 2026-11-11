import type { Settings as LayoutSettings } from '@ant-design/pro-components';
import type { RequestConfig, RunTimeLayoutConfig } from '@umijs/max';
import { history, Link } from '@umijs/max';
import React from "react";
import relativeTime from "dayjs/plugin/relativeTime";
import dayjs from "dayjs";

dayjs.extend(relativeTime);

import { ErrorBoundary, Footer, LangDropdown, OfflineBanner } from '@/components';
import FrontendDiagnostics from '@/components/FrontendDiagnostics';
import defaultSettings from '../config/defaultSettings';
import { errorConfig } from './requestErrorConfig';
import { clearAccessToken, getAccessToken, getCurrentUser, getSetupStatus, toCurrentUser } from './services/identity';
import { readThemeMode, resolveTheme, type ThemeMode } from './utils/theme';

const AppearanceSettings = React.lazy(() => import('./components/AppearanceSettings'));

const loginPath = '/user/login';

/** 启动时检查初始化状态和当前会话，未初始化时强制进入初始化向导。 */
export async function getInitialState(): Promise<{
  currentUser?: API.CurrentUser;
  fetchUserInfo?: () => Promise<API.CurrentUser | undefined>;
  settings?: Partial<LayoutSettings>;
  loading?: boolean;
  settingDrawerOpen?: boolean;
  initialized?: boolean;
  themeMode?: ThemeMode;
}> {
  const path = history.location.pathname;
  const setupPath = '/setup';
  const loginPathWithRedirect = `/user/login?redirect=${encodeURIComponent(path + history.location.search + history.location.hash)}`;
  let initialized = false;
  try {
    initialized = (await getSetupStatus()).data?.initialized ?? false;
  } catch {
    initialized = false;
  }

  if (!initialized && path !== setupPath) {
    history.replace(setupPath);
  } else if (initialized && path === setupPath) {
    history.replace(getAccessToken() ? '/overview' : loginPath);
  } else if (initialized && path === loginPath && getAccessToken()) {
    history.replace('/overview');
  } else if (initialized && path !== setupPath && path !== loginPath && !getAccessToken()) {
    history.replace(loginPathWithRedirect);
  }

  let currentUser: API.CurrentUser | undefined;
  if (initialized && getAccessToken() && path !== loginPath) {
    try {
      const response = await getCurrentUser();
      currentUser = response.data ? toCurrentUser(response.data) : undefined;
    } catch {
      clearAccessToken();
      history.replace(loginPathWithRedirect);
    }
  }

  return {
    currentUser,
    settings: defaultSettings as Partial<LayoutSettings>,
    settingDrawerOpen: false,
    initialized,
    themeMode: readThemeMode(),
  };
}

export const layout: RunTimeLayoutConfig = ({ initialState }) => ({
  menuItemRender: (item, dom) => (item.path ? <Link to={item.path}>{dom}</Link> : dom),
  actionsRender: () => [<LangDropdown key="lang" />],
  avatarProps: {
    title: 'Honeypot',
  },
  footerRender: () => <Footer />,
  onPageChange: () => {
    if (history.location.pathname === loginPath) {
      return;
    }
  },
  ErrorBoundary,
  childrenRender: (children) => (
    <>
      {children}
      <React.Suspense fallback={null}>
        <AppearanceSettings />
      </React.Suspense>
    </>
  ),
  ...(() => {
    const settings = initialState?.settings ?? defaultSettings;
    const themeMode = initialState?.themeMode ?? 'light';
    const navTheme = themeMode === 'auto' ? resolveTheme(themeMode) : themeMode;
    const token = (settings as LayoutSettings & { token?: Record<string, unknown> }).token ?? {};
    const colorPrimary = (settings as LayoutSettings & { colorPrimary?: string }).colorPrimary ?? defaultSettings.colorPrimary;
    return {
      ...settings,
      navTheme,
      token: {
        ...token,
        sider: {
          ...((token as { sider?: Record<string, unknown> }).sider ?? {}),
          colorTextMenuSelected: colorPrimary,
        },
      },
    };
  })(),
});

export const request: RequestConfig = {
  baseURL: process.env.HONEYPOT_API_BASE_URL || '',
  ...errorConfig,
};

export function rootContainer(container: React.ReactNode) {
  return (
    <>
      <FrontendDiagnostics />
      <OfflineBanner />
      <ErrorBoundary>{container}</ErrorBoundary>
    </>
  );
}
