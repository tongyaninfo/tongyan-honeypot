import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import * as api from '@/services/honeypot/api';
import { ipLocationClient } from '@/services/honeypot/ipLocationClient';
import IPLocationSettingsPage from './index';

vi.mock('@umijs/max', () => ({ request: vi.fn() }));
vi.mock('@/services/honeypot/api', async (original) => ({ ...await original<typeof api>(), getIPLocationSettings: vi.fn(), saveIPLocationSettings: vi.fn() }));
const response = { success: true, code: 'OK', message: '', data: api.defaultIPLocationSettings };
beforeEach(() => { vi.clearAllMocks(); vi.mocked(api.getIPLocationSettings).mockResolvedValue(response); });
afterEach(() => { cleanup(); vi.restoreAllMocks(); });

it('loads the disabled public defaults, attribution and six single-choice databases', async () => {
  render(<IPLocationSettingsPage />);
  expect(await screen.findByDisplayValue('ip.tongyaninfo.com')).toBeInTheDocument();
  await waitFor(() => expect(screen.getByRole('button', { name: '保存配置' })).toBeEnabled());
  expect(screen.getByText('通研IP适配器')).toBeInTheDocument();
  expect(screen.getByRole('link', { name: 'ip.tongyaninfo.com' })).toHaveAttribute('href', 'https://ip.tongyaninfo.com/');
  expect(screen.getByRole('switch')).toHaveAttribute('aria-checked', 'false');
  expect(screen.getByRole('spinbutton', { name: '端口' })).toHaveValue('443');
  expect(screen.getByRole('spinbutton', { name: '解析超时时间（秒）' })).toHaveAttribute('aria-valuenow', '2');
  fireEvent.mouseDown(screen.getByRole('combobox', { name: 'IP 数据库' }));
  for (const database of ['CZ88', 'ip2location', 'ip2region', 'dbip', 'ipinfo', 'geolite2']) {
    expect(screen.getAllByText(database).length).toBeGreaterThan(0);
  }
});

it('saves the enabled configuration and invalidates visible location results', async () => {
  const invalidate = vi.spyOn(ipLocationClient, 'invalidate');
  vi.mocked(api.saveIPLocationSettings).mockResolvedValue({ ...response, data: { ...response.data, enabled: true } });
  render(<IPLocationSettingsPage />);
  await waitFor(() => expect(screen.getByRole('button', { name: '保存配置' })).toBeEnabled());
  fireEvent.click(screen.getByRole('switch'));
  fireEvent.click(screen.getByRole('button', { name: '保存配置' }));
  await screen.findByText('IP 数据库配置已保存。');
  expect(api.saveIPLocationSettings).toHaveBeenCalledWith({ ...api.defaultIPLocationSettings, enabled: true });
  expect(invalidate).toHaveBeenCalledOnce();
});

it('prevents replacing a configuration that could not be loaded', async () => {
  vi.mocked(api.getIPLocationSettings).mockRejectedValue(new Error('Forbidden'));
  render(<IPLocationSettingsPage />);
  await screen.findByText('无法读取配置，请检查管理员权限或稍后重试。');
  expect(screen.getByRole('button', { name: '保存配置' })).toBeDisabled();
  expect(api.saveIPLocationSettings).not.toHaveBeenCalled();
});
