import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import * as api from '@/services/honeypot/syslog';
import SyslogPage from './index';

vi.mock('@umijs/max', () => ({ request: vi.fn(), useAccess: () => ({ canAdmin: true }) }));
vi.mock('@/services/honeypot/syslog', async (original) => ({ ...await original<typeof api>(), getSyslogSettings: vi.fn(), saveSyslogSettings: vi.fn(), getSyslogStatus: vi.fn(), testSyslogTarget: vi.fn() }));
const target: api.SyslogTarget = { id: 'target-1', name: 'Synthetic Syslog', host: 'syslog.example.invalid', port: 6514, protocol: 'Tls', enabled: true, ignoreSslErrors: false };
const legacyTarget = { ...target, ignoredSeverities: [7], facility: 23 };
const response = { success: true, code: 'OK', message: '', data: { settings: { ...api.defaultSyslogSettings, targets: [legacyTarget] }, revision: 7, hostname: 'tongyan-honeypot-TEST' } };
beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(api.getSyslogSettings).mockResolvedValue(structuredClone(response));
  vi.mocked(api.getSyslogStatus).mockResolvedValue({ success: true, code: 'OK', message: '', data: { enabled: false, hostname: response.data.hostname, targets: [{ targetId: target.id, state: 'Disabled', pendingCount: 0, sentCount: 0, confirmedCount: 0, failedCount: 0, retriedCount: 0, droppedCount: 0, truncatedCount: 0 }] } });
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.unstubAllGlobals(); });

it('loads disabled settings with TLS verification enabled and readonly hostname', async () => {
  render(<SyslogPage />);
  expect(await screen.findByDisplayValue(target.host)).toBeInTheDocument();
  expect(screen.getByText('tongyan-honeypot-TEST')).toBeInTheDocument();
  expect(screen.getByRole('checkbox', { name: '忽略 SSL 错误' })).not.toBeChecked();
  expect(screen.getByRole('switch', { name: '启用 Syslog' })).toHaveAttribute('aria-checked', 'false');
  expect(screen.queryByRole('textbox', { name: '主机名' })).not.toBeInTheDocument();
  expect(screen.queryByLabelText(/忽略的严重级别|Facility/)).not.toBeInTheDocument();
});

it('sends a custom test message to the saved target with forwarding disabled', async () => {
  vi.mocked(api.saveSyslogSettings).mockResolvedValue({ ...response, data: { ...response.data, revision: 8 } });
  vi.mocked(api.testSyslogTarget).mockResolvedValue({ success: true, code: 'OK', message: '', data: { targetId: target.id, correlationId: 'test-correlation', succeeded: true, stage: 'Written' } });
  render(<SyslogPage />);
  await waitFor(() => expect(screen.getByRole('button', { name: '保存 Syslog 配置' })).toBeEnabled());
  fireEvent.change(screen.getByRole('textbox', { name: '服务器地址 1' }), { target: { value: 'unsaved.example.invalid' } });
  fireEvent.change(screen.getByRole('textbox', { name: '消息内容' }), { target: { value: '  合成测试消息  ' } });
  fireEvent.click(await screen.findByRole('button', { name: '发送测试消息' }));
  await screen.findByText(/test-correlation/);
  expect(api.testSyslogTarget).toHaveBeenCalledWith('target-1', '合成测试消息');
  expect(api.saveSyslogSettings).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', { name: '保存 Syslog 配置' }));
  await waitFor(() => expect(api.saveSyslogSettings).toHaveBeenCalled());
  expect(vi.mocked(api.saveSyslogSettings).mock.calls[0][1]).toBe(7);
  const savedTarget = vi.mocked(api.saveSyslogSettings).mock.calls[0][0].targets[0];
  expect(savedTarget.host).toBe('unsaved.example.invalid');
  expect(savedTarget).not.toHaveProperty('ignoredSeverities');
  expect(savedTarget).not.toHaveProperty('facility');
});

it('requires a saved target selection for default test messages when several targets exist', async () => {
  const second = { ...target, id: 'target-2', name: 'Second Syslog', host: 'second.example.invalid' };
  vi.mocked(api.getSyslogSettings).mockResolvedValue({
    ...response,
    data: { ...response.data, settings: { ...api.defaultSyslogSettings, targets: [legacyTarget, { ...second, ignoredSeverities: [], facility: 16 }] } },
  });
  vi.mocked(api.testSyslogTarget).mockResolvedValue({ success: true, code: 'OK', message: '', data: { targetId: second.id, correlationId: 'default-correlation', succeeded: true, stage: 'Written' } });
  render(<SyslogPage />);
  await screen.findByDisplayValue(second.host);
  const send = screen.getByRole('button', { name: '发送测试消息' });
  expect(send).toBeDisabled();
  fireEvent.mouseDown(screen.getByRole('combobox', { name: '测试目标' }));
  fireEvent.click(await screen.findByText(/Second Syslog（/));
  await waitFor(() => expect(send).toBeEnabled());
  fireEvent.click(send);
  await screen.findByText(/default-correlation/);
  expect(api.testSyslogTarget).toHaveBeenCalledWith(second.id, undefined);
});

it('blocks saving a configuration that could not be loaded', async () => {
  vi.mocked(api.getSyslogSettings).mockRejectedValue(new Error('Unavailable'));
  render(<SyslogPage />);
  await screen.findByText('无法读取配置，已暂停保存。');
  expect(screen.getByRole('button', { name: '保存 Syslog 配置' })).toBeDisabled();
});

it('adds a target on an HTTP console without crypto.randomUUID', async () => {
  vi.stubGlobal('crypto', { getRandomValues: crypto.getRandomValues.bind(crypto) });
  vi.mocked(api.saveSyslogSettings).mockResolvedValue(response);
  render(<SyslogPage />);
  await screen.findByDisplayValue(target.host);
  const add = screen.getByRole('button', { name: /添加目标/ });
  await waitFor(() => expect(add).toBeEnabled());
  fireEvent.click(add);
  fireEvent.change(screen.getByRole('textbox', { name: '服务器地址 2' }), { target: { value: 'second.example.invalid' } });
  fireEvent.click(screen.getByRole('button', { name: '保存 Syslog 配置' }));
  await waitFor(() => expect(api.saveSyslogSettings).toHaveBeenCalled());
  expect(vi.mocked(api.saveSyslogSettings).mock.calls[0][0].targets[1].id).toMatch(/^target-[a-f0-9]{32}$/);
});

it('keeps custom ports and resets ignored certificate errors when switching protocols', async () => {
  render(<SyslogPage />);
  await screen.findByDisplayValue(target.host);
  await waitFor(() => expect(screen.getByRole('button', { name: '保存 Syslog 配置' })).toBeEnabled());
  fireEvent.click(screen.getByRole('checkbox', { name: '忽略 SSL 错误' }));
  expect(await screen.findByText('未验证服务器身份')).toBeInTheDocument();
  fireEvent.change(screen.getByRole('spinbutton', { name: '端口 1' }), { target: { value: '15140' } });
  fireEvent.mouseDown(screen.getByRole('combobox', { name: '协议 1' }));
  fireEvent.click(screen.getByText('TCP'));
  await waitFor(() => expect(screen.queryByRole('checkbox', { name: '忽略 SSL 错误' })).not.toBeInTheDocument());
  expect(screen.getByRole('spinbutton', { name: '端口 1' })).toHaveValue('15140');
  fireEvent.mouseDown(screen.getByRole('combobox', { name: '协议 1' }));
  fireEvent.click(screen.getByText('TLS'));
  expect(await screen.findByRole('checkbox', { name: '忽略 SSL 错误' })).not.toBeChecked();
  expect(screen.getByRole('spinbutton', { name: '端口 1' })).toHaveValue('15140');
});
