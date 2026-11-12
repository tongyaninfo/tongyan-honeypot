import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import * as api from '@/services/honeypot/mcp';
import McpPage from './index';

vi.mock('@umijs/max', () => ({ request: vi.fn(), useAccess: () => ({ canAdmin: true }) }));
vi.mock('@/services/honeypot/mcp', async (original) => ({
  ...await original<typeof api>(),
  getMcpSettings: vi.fn(), getMcpPermissions: vi.fn(), getMcpKeys: vi.fn(), createMcpKey: vi.fn(),
  getMcpAudits: vi.fn(), getMcpAudit: vi.fn(), updateMcpSettings: vi.fn(),
}));

const key: api.McpKey = {
  id: 'key-test', name: '值班助手', prefix: 'mcp-test', access: 'ReadOnly', status: 'Active',
  permissionIds: ['get_overview'], instanceIds: [], createdAtUtc: '2026-11-11T12:30:00Z',
};
const audit: api.McpAuditSummary = {
  id: 'audit-test', occurredAtUtc: '2026-11-11T12:30:30Z', tool: 'get_overview', keyName: '值班助手',
  keyId: 'key-test', sourceIp: '192.0.2.12', httpStatus: 200, result: 'ToolError', durationMs: 17,
};
const settings: api.McpSettings = { enabled: false, auditRetentionDays: 30, auditAvailable: true };
const ok = <T,>(data: T) => ({ success: true, code: 'OK', message: '', data });
const page = <T,>(item: T) => ok({ items: [item], total: 1, page: 1, pageSize: 20 });

async function modalByTitle(title: string) {
  const heading = await screen.findByText(title, { selector: '.ant-modal-title' });
  const dialog = heading.closest<HTMLElement>('[role="dialog"]');
  if (!dialog) throw new Error(`Missing dialog for ${title}`);
  return within(dialog);
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(api.getMcpSettings).mockResolvedValue(ok(settings));
  vi.mocked(api.getMcpPermissions).mockResolvedValue(ok({
    groups: [{ id: 'runtime', label: '运行', tools: [
      { id: 'get_overview', label: '查看总览', description: '', access: 'ReadOnly' },
      { id: 'start_service_instance', label: '启动实例', description: '', access: 'ReadWrite', requiresInstanceScope: true },
    ] }],
    instances: [{ id: 'instance-test', name: '隔离实例' }],
  }));
  vi.mocked(api.getMcpKeys).mockResolvedValue(page(key));
  vi.mocked(api.createMcpKey).mockResolvedValue(ok({ key, secret: 'one-time-synthetic-value' }));
  vi.mocked(api.getMcpAudits).mockResolvedValue(page(audit));
  vi.mocked(api.getMcpAudit).mockResolvedValue(ok({ ...audit, mcpMethod: 'tools/call', responseBody: '<b>合成响应</b>' }));
  vi.mocked(api.updateMcpSettings).mockResolvedValue(ok({ ...settings, auditRetentionDays: 14 }));
});
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

it('clears the write grant and instance scope when returning to read-only mode', async () => {
  render(<McpPage />);
  const create = await screen.findByRole('button', { name: '新建 API Key' });
  await waitFor(() => expect(create).toBeEnabled());
  fireEvent.click(create);
  const dialog = await modalByTitle('新建 API Key');
  const writeGrant = dialog.getByRole('checkbox', { name: /启动实例/ });
  expect(writeGrant).toHaveAttribute('aria-disabled', 'true');
  act(() => dialog.getByRole('radio', { name: '读写' }).click());
  await waitFor(() => expect(writeGrant).toHaveAttribute('aria-disabled', 'false'));
  fireEvent.click(writeGrant);
  expect(dialog.getByRole('combobox', { name: '可管理实例' })).toBeInTheDocument();
  act(() => dialog.getByRole('radio', { name: '只读' }).click());
  expect(dialog.queryByRole('combobox', { name: '可管理实例' })).not.toBeInTheDocument();
  expect(writeGrant).toHaveAttribute('aria-checked', 'false');
  fireEvent.click(dialog.getByRole('checkbox', { name: '查看总览' }));
  fireEvent.change(dialog.getByRole('textbox', { name: '名称' }), { target: { value: ' 值班助手 ' } });
  fireEvent.click(dialog.getByRole('button', { name: /创\s*建/ }));
  const success = await modalByTitle('API Key 已创建');
  expect(api.createMcpKey).toHaveBeenCalledWith({ name: '值班助手', access: 'ReadOnly', permissionIds: ['get_overview'], instanceIds: [], expiresAtUtc: undefined });
  expect(success.getByText('one-time-synthetic-value')).toBeInTheDocument();
  fireEvent.click(success.getByRole('button', { name: /关\s*闭/ }));
  expect(screen.queryByText('one-time-synthetic-value')).not.toBeInTheDocument();
});

it('opens a selectable instruction without the key if the clipboard write fails', async () => {
  const write = vi.spyOn(navigator.clipboard, 'writeText').mockRejectedValue(new Error('Clipboard unavailable'));
  render(<McpPage />);
  fireEvent.click(await screen.findByRole('button', { name: '复制接入指令' }));
  await waitFor(() => expect(write).toHaveBeenCalledOnce());
  const dialog = await modalByTitle('MCP 接入指令');
  expect(dialog.getByText(/MCP Endpoint:/)).toHaveTextContent(`${window.location.origin}/mcp`);
  expect(dialog.getByText(/MCP Endpoint:/)).toHaveTextContent(/Authorization: Bearer \$\{HONEYPOT_MCP_API_KEY\}/);
});

it('loads audit bodies on demand and displays the original response as text', async () => {
  render(<McpPage />);
  expect(api.getMcpAudits).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('tab', { name: '调用记录' }));
  const row = await screen.findByRole('button', { name: 'get_overview' });
  expect(screen.getByText('工具失败')).toBeInTheDocument();
  expect(api.getMcpAudit).not.toHaveBeenCalled();
  fireEvent.click(row);
  fireEvent.click(await screen.findByRole('tab', { name: '响应' }));
  const response = await screen.findByText('<b>合成响应</b>');
  expect(response.querySelector('b')).toBeNull();
  expect(api.getMcpAudit).toHaveBeenCalledWith('audit-test', expect.any(AbortSignal));
});

it('copies the stored audit response and offers the raw text if clipboard access fails', async () => {
  const raw = String.raw`{"message":"\u5B8C\u6210"}`;
  vi.mocked(api.getMcpAudit).mockResolvedValue(ok({ ...audit, responseBody: raw }));
  const write = vi.spyOn(navigator.clipboard, 'writeText').mockResolvedValueOnce(undefined).mockRejectedValueOnce(new Error('Clipboard unavailable'));
  render(<McpPage />);
  fireEvent.click(screen.getByRole('tab', { name: '调用记录' }));
  fireEvent.click(await screen.findByRole('button', { name: 'get_overview' }));
  fireEvent.click(await screen.findByRole('tab', { name: '响应' }));
  const preview = await screen.findByText(/"message": "完成"/);
  expect(preview.textContent).toBe('{\n  "message": "完成"\n}');
  const copy = screen.getByRole('button', { name: '复制响应体' });
  fireEvent.click(copy);
  await waitFor(() => expect(write).toHaveBeenCalledWith(raw));
  expect(preview.textContent).toContain('完成');
  fireEvent.click(copy);
  await waitFor(() => expect(preview.textContent).toBe(raw));
});
