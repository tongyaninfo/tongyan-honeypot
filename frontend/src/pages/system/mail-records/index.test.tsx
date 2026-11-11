import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import * as api from '@/services/honeypot/notifications';
import MailRecordsPage from './index';

const location = vi.hoisted(() => ({ search: '' }));
vi.mock('@umijs/max', () => ({ request: vi.fn(), useLocation: () => location, useAccess: () => ({ canAdmin: true }) }));
vi.mock('@/services/honeypot/notifications', async (original) => ({ ...await original<typeof api>(), getEmailDeliveries: vi.fn(), getEmailDelivery: vi.fn(), retryEmailDelivery: vi.fn() }));
const row: api.EmailDeliverySummary = { id: 'mail-1', kind: 'Daily', recipient: 'security@example.test', subject: '运行日报', status: 'Accepted', createdAtUtc: '2026-11-10T00:00:00Z', sentAtUtc: '2026-11-10T00:01:00Z', attemptCount: 1 };
const details: api.EmailDeliveryDetails = { delivery: row, htmlBody: '<h1>安全报告</h1>', textBody: '安全报告', templateVersion: 'v1', attempts: [], canRetry: false };
const ok = <T,>(data: T) => ({ success: true, code: 'OK', message: '', data });
beforeEach(() => { vi.clearAllMocks(); location.search = ''; vi.mocked(api.getEmailDeliveries).mockResolvedValue(ok({ items: [row], total: 1, page: 1, pageSize: 20 })); vi.mocked(api.getEmailDelivery).mockResolvedValue(ok(details)); });
afterEach(cleanup);

it('loads sent mail with server-side status filtering and isolates the detail HTML', async () => {
  render(<MailRecordsPage />);
  fireEvent.click(await screen.findByRole('button', { name: '运行日报' }));
  expect(await screen.findByTitle('邮件内容预览')).toHaveAttribute('sandbox', '');
  expect(api.getEmailDeliveries).toHaveBeenCalledWith({ page: 1, pageSize: 20, status: 'Accepted' }, expect.any(AbortSignal));
  expect(screen.getByText('“SMTP 已受理”表示邮件服务器接受了发送请求，不代表收件人已收到或已读。')).toBeInTheDocument();
  expect(screen.queryByRole('button', { name: '重新发送' })).not.toBeInTheDocument();
});

it('opens a queued test task from its link without restricting to accepted messages', async () => {
  location.search = '?status=all&id=mail-1';
  render(<MailRecordsPage />);
  await screen.findByTitle('邮件内容预览');
  expect(api.getEmailDeliveries).toHaveBeenCalledWith({ page: 1, pageSize: 20, status: undefined }, expect.any(AbortSignal));
  expect(api.getEmailDelivery).toHaveBeenCalledWith('mail-1', expect.any(AbortSignal));
});
