import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import * as api from '@/services/honeypot/notifications';
import NotificationSettingsPage from './index';

const access = vi.hoisted(() => ({ canAdmin: true }));
vi.mock('@umijs/max', () => ({ request: vi.fn(), useAccess: () => access, Link: ({ to, children }: { to: string; children: React.ReactNode }) => <a href={to}>{children}</a> }));
vi.mock('@/services/honeypot/notifications', async (original) => ({ ...await original<typeof api>(), getNotificationSettings: vi.fn(), saveNotificationSettings: vi.fn(), sendTestEmail: vi.fn() }));
const settings = { ...api.defaultNotificationSettings, enabled: true, host: 'smtp.example.test', fromEmail: 'sender@example.test', username: 'sender@example.test', hasCredential: true, defaultRecipients: ['security@example.test'] };
const ok = <T,>(data: T) => ({ success: true, code: 'OK', message: '', data });

beforeEach(() => { vi.clearAllMocks(); access.canAdmin = true; vi.mocked(api.getNotificationSettings).mockResolvedValue(ok(settings)); vi.mocked(api.saveNotificationSettings).mockResolvedValue(ok(settings)); });
afterEach(cleanup);

it('keeps an existing authorization code write-only when saving unchanged settings', async () => {
  render(<NotificationSettingsPage />);
  await screen.findByDisplayValue('smtp.example.test');
  expect(screen.getByLabelText('邮箱授权码')).toHaveValue('');
  expect(screen.getByRole('checkbox', { name: '启用 SSL/TLS 加密（推荐）' })).toBeChecked();
  fireEvent.click(screen.getByRole('button', { name: '保存通知设置' }));
  await screen.findByText('通知设置已保存。');
  expect(api.saveNotificationSettings).toHaveBeenCalledOnce();
  const [saved, authorizationCode] = vi.mocked(api.saveNotificationSettings).mock.calls[0];
  expect(authorizationCode).toBe('');
  expect(saved.host).toBe('smtp.example.test');
  expect(saved.defaultRecipients).toEqual(['security@example.test']);
  expect(saved.schedules).toHaveLength(3);
  expect(saved).not.toHaveProperty('authorizationCode');
});

it('uses saved configuration for a test and reports queue IDs instead of claiming delivery', async () => {
  vi.mocked(api.sendTestEmail).mockResolvedValue(ok({ deliveryIds: ['mail-test-1'], message: 'queued' }));
  render(<NotificationSettingsPage />);
  await screen.findByDisplayValue('smtp.example.test');
  fireEvent.change(screen.getByLabelText('邮件服务器地址'), { target: { value: 'unsaved.example.test' } });
  fireEvent.click(screen.getByRole('button', { name: '测试发送邮件' }));
  fireEvent.click(await screen.findByRole('button', { name: '提交测试邮件' }));
  await screen.findByText('测试邮件已加入队列，发送结果请查看邮件记录。');
  expect(api.sendTestEmail).toHaveBeenCalledWith('security@example.test');
  expect(api.saveNotificationSettings).not.toHaveBeenCalled();
  expect(screen.getByText('任务：mail-test-1')).toBeInTheDocument();
});

it('blocks overwriting settings after a failed load', async () => {
  vi.mocked(api.getNotificationSettings).mockRejectedValue(new Error('forbidden'));
  render(<NotificationSettingsPage />);
  await screen.findByText('无法读取通知设置，已暂停保存。');
  await waitFor(() => expect(screen.getByRole('button', { name: '保存通知设置' })).toBeDisabled());
  expect(screen.getByRole('button', { name: '测试发送邮件' })).toBeDisabled();
});

it('keeps administrators-only configuration requests behind the role gate', () => {
  access.canAdmin = false;
  render(<NotificationSettingsPage />);
  expect(screen.getByText('仅管理员可访问通知设置。')).toBeInTheDocument();
  expect(api.getNotificationSettings).not.toHaveBeenCalled();
});

it('submits an explicit None mode when SSL is disabled', async () => {
  render(<NotificationSettingsPage />);
  await screen.findByDisplayValue('smtp.example.test');
  fireEvent.click(screen.getByRole('checkbox', { name: '启用 SSL/TLS 加密（推荐）' }));
  fireEvent.click(screen.getByRole('button', { name: '保存通知设置' }));
  await waitFor(() => expect(api.saveNotificationSettings).toHaveBeenCalledWith(expect.objectContaining({ useSsl: false, securityMode: 'None' }), ''));
});
