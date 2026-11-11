import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import * as api from '@/services/honeypot/api';
import { connectHoneypotRealtime } from '@/services/realtime';
import ServicesPage from './index';

vi.mock('@umijs/max', () => ({ request: vi.fn() }));
vi.mock('@/services/honeypot/api', async (original) => ({
  ...await original<typeof api>(),
  createServiceInstance: vi.fn(),
  getListeners: vi.fn(),
  getServiceInstances: vi.fn(),
  getServiceTypes: vi.fn(),
}));
vi.mock('@/services/realtime', () => ({
  connectHoneypotRealtime: vi.fn().mockResolvedValue(async () => {}),
}));

const serviceTypes: api.ServiceType[] = [
  { adapterKey: 'rdp', displayName: 'RDP' },
  { adapterKey: 'ssh', displayName: 'SSH' },
  { adapterKey: 'mysql', displayName: 'MySQL' },
  { adapterKey: 'mssql', displayName: 'MSSQL' },
  { adapterKey: 'mongodb', displayName: 'MongoDB' },
].map((serviceType) => ({
  ...serviceType,
  transport: ['tcp'],
  adapterVersion: '1',
  supportedFidelityLevels: [],
  capabilities: [],
}));

const rdpBinding: api.ListenerBinding = {
  listenerId: 'rdp-listener',
  bindAddress: '0.0.0.0',
  port: 3389,
  transport: 'tcp',
  enabled: true,
};

const rdpInstance: api.ServiceInstance = {
  instanceId: 'rdp-instance',
  adapterKey: 'rdp',
  displayName: 'RDP 蜜罐',
  profile: { profileId: 'rdp-profile', adapterKey: 'rdp' },
  bindings: [rdpBinding],
};

const ok = <T,>(data: T) => ({ success: true, code: 'OK', message: '', data });
const page = <T,>(items: T[]) => ({ items, total: items.length, page: 1, pageSize: 20 });

afterEach(cleanup);

it('groups adapters into tabs and keeps a port draft through switching and realtime refresh', async () => {
  vi.mocked(api.getServiceTypes).mockResolvedValue(ok(serviceTypes));
  vi.mocked(api.getServiceInstances).mockResolvedValue(ok(page([rdpInstance])));
  vi.mocked(api.getListeners).mockResolvedValue(ok(page([])));

  render(<ServicesPage />);

  const systemTab = await screen.findByRole('tab', { name: /^系统/ });
  const databaseTab = screen.getByRole('tab', { name: /^数据库/ });
  expect(systemTab).toHaveAttribute('aria-selected', 'true');
  const system = within(screen.getByRole('tabpanel', { name: /^系统/ }));
  expect(system.getByText(/^Windows\b/)).toBeInTheDocument();
  expect(system.getByText(/^Linux\b/)).toBeInTheDocument();
  expect(system.getByText('RDP')).toBeInTheDocument();
  expect(system.getAllByText('SSH')[0]).toBeInTheDocument();
  expect(system.queryByText('MySQL')).not.toBeInTheDocument();

  fireEvent.change(system.getByDisplayValue('3389'), { target: { value: '3390' } });
  expect(system.getByText('有未应用的端口修改')).toBeInTheDocument();

  fireEvent.click(databaseTab);
  expect(databaseTab).toHaveAttribute('aria-selected', 'true');
  const databases = within(screen.getByRole('tabpanel', { name: /^数据库/ }));
  expect(databases.getAllByText('MySQL')[0]).toBeInTheDocument();
  expect(databases.getAllByText('MSSQL')[0]).toBeInTheDocument();
  expect(databases.getAllByText('MongoDB')[0]).toBeInTheDocument();
  expect(databases.queryByText('RDP')).not.toBeInTheDocument();

  vi.mocked(api.getListeners).mockResolvedValue(ok(page([
    { ...rdpBinding, instanceId: rdpInstance.instanceId, state: 'Running', activeConnections: 2, acceptedCount: 4 },
  ])));
  await act(async () => {
    vi.mocked(connectHoneypotRealtime).mock.calls[0][0].onRuntime?.();
  });

  expect(screen.getByRole('tab', { name: /^数据库/ })).toHaveAttribute('aria-selected', 'true');
  fireEvent.click(screen.getByRole('tab', { name: /^系统/ }));
  const refreshedSystem = within(screen.getByRole('tabpanel', { name: /^系统/ }));
  expect(refreshedSystem.getByDisplayValue('3390')).toBeInTheDocument();
  expect(refreshedSystem.getByText('有未应用的端口修改')).toBeInTheDocument();
  expect(refreshedSystem.getByText('连接 2 / 已接收 4')).toBeInTheDocument();
  expect(api.createServiceInstance).not.toHaveBeenCalled();
});

it('uses backend defaults for new adapters and preserves existing names and ports', async () => {
  const additions: api.ServiceType[] = [
    ['smb', 'SMB', 445, 'system', 'Windows'],
    ['telnet', 'Telnet', 23, 'system', 'Linux'],
    ['nfs', 'NFS', 2049, 'system', 'Linux'],
    ['postgresql', 'PostgreSQL', 5432, 'database'],
    ['redis', 'Redis', 6379, 'database'],
    ['oracle', 'Oracle', 1521, 'database'],
    ['db2', 'IBM Db2', 50000, 'database'],
    ['memcached', 'Memcached', 11211, 'database'],
    ['hbase', 'HBase', 16020, 'database'],
    ['influxdb', 'InfluxDB', 8086, 'database'],
    ['elasticsearch', 'Elasticsearch', 9200, 'database'],
  ].map(([key, name, port, category, group]) => ({
    ...serviceTypes[0], adapterKey: String(key), displayName: String(name), defaultInstanceName: String(name),
    defaultPort: Number(port), category: String(category), systemGroup: group ? String(group) : undefined,
    defaultHostName: `${key}-test`, defaultProduct: String(name), defaultProductVersion: '1.0',
  }));
  vi.mocked(api.getServiceTypes).mockResolvedValue(ok([...serviceTypes, ...additions]));
  vi.mocked(api.getServiceInstances).mockResolvedValue(ok(page([{ ...rdpInstance, displayName: '现有服务', bindings: [{ ...rdpBinding, port: 33389 }] }])));
  vi.mocked(api.getListeners).mockResolvedValue(ok(page([])));
  render(<ServicesPage />);
  await screen.findByRole('tab', { name: /^系统/ });
  expect(screen.getByText('现有服务')).toBeInTheDocument();
  expect(screen.getByDisplayValue('33389')).toBeInTheDocument();
  for (const [key, port] of [['smb', 445], ['telnet', 23], ['nfs', 2049]]) {
    expect(within(screen.getByTestId(`service-card-${key}`)).getByDisplayValue(String(port))).toBeInTheDocument();
  }
  fireEvent.click(screen.getByRole('tab', { name: /^数据库/ }));
  const databases = within(screen.getByRole('tabpanel', { name: /^数据库/ }));
  for (const type of additions.filter((item) => item.category === 'database')) {
    const card = within(databases.getByTestId(`service-card-${type.adapterKey}`));
    expect(card.getByDisplayValue(String(type.defaultPort))).toBeInTheDocument();
    expect(card.getAllByText(type.displayName).length).toBeGreaterThan(0);
  }
  expect(databases.queryByText(/TDSQL/i)).not.toBeInTheDocument();
  expect(api.createServiceInstance).not.toHaveBeenCalled();
});

it('shows a conflicting default port without silently incrementing it or creating an instance', async () => {
  vi.mocked(api.getServiceTypes).mockResolvedValue(ok([
    ...serviceTypes,
    { ...serviceTypes[0], adapterKey: 'redis', displayName: 'Redis', defaultPort: 6379, category: 'database' },
  ]));
  vi.mocked(api.getServiceInstances).mockResolvedValue(ok(page([{ ...rdpInstance, bindings: [{ ...rdpBinding, port: 6379 }] }])));
  vi.mocked(api.getListeners).mockResolvedValue(ok(page([])));
  render(<ServicesPage />);
  fireEvent.click(await screen.findByRole('tab', { name: /^数据库/ }));
  const card = within(screen.getByTestId('service-card-redis'));
  expect(card.getByDisplayValue('6379')).toBeInTheDocument();
  expect(card.getByText(/端口冲突：6379/)).toBeInTheDocument();
  fireEvent.click(card.getByRole('button', { name: /启\s*动/ }));
  expect(api.createServiceInstance).not.toHaveBeenCalled();
});
