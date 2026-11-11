import { request } from '@umijs/max';
import type { ApiResult } from './honeypot/api';

const tokenKey = 'honeypot.access_token';

export interface SetupStatus {
  initialized: boolean;
}

export interface IdentityUser {
  userId: string;
  username: string;
  roles: string[];
}

export interface LoginResult {
  accessToken: string;
  expiresAtUtc: string;
  user: IdentityUser;
}

/** 将真实身份合同转换为管理布局使用的字段，角色保留服务端返回值。 */
export function toCurrentUser(user: IdentityUser): API.CurrentUser {
  return { userid: user.userId, name: user.username, roles: [...user.roles] };
}

export function getAccessToken() {
  if (typeof window === 'undefined') return undefined;
  return window.sessionStorage.getItem(tokenKey) ?? undefined;
}

export function setAccessToken(token: string) {
  window.sessionStorage.setItem(tokenKey, token);
}

export function clearAccessToken() {
  if (typeof window !== 'undefined') window.sessionStorage.removeItem(tokenKey);
}

export async function getSetupStatus() {
  return request<ApiResult<SetupStatus>>('/api/v1/setup/status', { method: 'GET' });
}

export async function initializeSystem(data: { username: string; password: string }) {
  return request<ApiResult<IdentityUser>>('/api/v1/setup/initialize', {
    method: 'POST',
    data,
  });
}

export async function login(data: { username: string; password: string }) {
  return request<ApiResult<LoginResult>>('/api/v1/auth/login', {
    method: 'POST',
    data,
  });
}

export async function getCurrentUser() {
  return request<ApiResult<IdentityUser>>('/api/v1/auth/me', { method: 'GET' });
}

export async function logout() {
  return request<ApiResult<unknown>>('/api/v1/auth/logout', { method: 'POST' });
}
