import { act, cleanup, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import * as api from '@/services/honeypot/api';
import { ipLocationClient } from '@/services/honeypot/ipLocationClient';
import SourceIp from './index';

vi.mock('@umijs/max', () => ({ request: vi.fn() }));
vi.mock('@/services/honeypot/api', async (original) => ({ ...await original<typeof api>(), resolveIPLocations: vi.fn() }));

beforeEach(() => { vi.useFakeTimers(); ipLocationClient.invalidate(); vi.clearAllMocks(); });
afterEach(() => { cleanup(); ipLocationClient.invalidate(); vi.clearAllTimers(); vi.useRealTimers(); });

it('shows the IP link immediately and fills its separate location line later', async () => {
  vi.mocked(api.resolveIPLocations).mockResolvedValue({ success: true, code: 'OK', message: '', data: {
    enabled: true, items: [{ ip: '1.1.1.1', status: 'resolved', country: '中国', province: '江苏省', city: '南京市', district: '鼓楼区' }],
  } });
  render(<SourceIp ip="1.1.1.1"><a href="/events?sourceIp=1.1.1.1">1.1.1.1</a></SourceIp>);
  expect(screen.getByRole('link', { name: '1.1.1.1' })).toHaveAttribute('href', '/events?sourceIp=1.1.1.1');
  expect(screen.getByText('归属地解析中…')).toBeInTheDocument();
  await act(async () => { await vi.advanceTimersByTimeAsync(30); });
  const location = screen.getByText('中国 · 江苏省 · 南京市 · 鼓楼区');
  expect(location.parentElement).toHaveStyle({ flexDirection: 'column' });
});

it('shows disabled and local classifications without blanking the original IP', async () => {
  vi.mocked(api.resolveIPLocations).mockResolvedValue({ success: true, code: 'OK', message: '', data: {
    enabled: false, items: [{ ip: '1.1.1.1', status: 'disabled' }, { ip: '192.0.2.0/24', status: 'network', displayName: '网段' }],
  } });
  render(<><SourceIp ip="1.1.1.1" /><SourceIp ip="192.0.2.0/24" /></>);
  await act(async () => { await vi.advanceTimersByTimeAsync(30); });
  expect(screen.getByText('1.1.1.1')).toBeInTheDocument();
  expect(screen.getByText('IP 解析已关闭')).toBeInTheDocument();
  expect(screen.getByText('网段')).toBeInTheDocument();
  expect(api.resolveIPLocations).toHaveBeenCalledOnce();
});

it('keeps an overlong input out of the batch so a normal IP still resolves', async () => {
  vi.mocked(api.resolveIPLocations).mockResolvedValue({ success: true, code: 'OK', message: '', data: {
    enabled: true, items: [{ ip: '1.1.1.1', status: 'resolved', country: '示例国家' }],
  } });
  render(<><SourceIp ip={'a'.repeat(81)} /><SourceIp ip="1.1.1.1" /></>);
  expect(screen.getByText('无效 IP 地址')).toBeInTheDocument();
  await act(async () => { await vi.advanceTimersByTimeAsync(30); });
  expect(api.resolveIPLocations).toHaveBeenCalledExactlyOnceWith(['1.1.1.1'], expect.any(AbortSignal));
  expect(screen.getByText('示例国家')).toBeInTheDocument();
});
