import { Typography } from 'antd';
import { type ReactNode, useCallback, useSyncExternalStore } from 'react';
import { type IPLocationResult, maxIPLocationInputLength } from '@/services/honeypot/api';
import { ipLocationClient } from '@/services/honeypot/ipLocationClient';

const statusLabels: Record<IPLocationResult['status'], string> = {
  disabled: 'IP 解析已关闭', pending: '归属地解析中…', resolved: '未查询到归属地',
  private: '内网地址', reserved: '保留地址', network: '网段', failed: '归属地暂不可用',
  invalid: '无效 IP 地址', busy: '解析排队中…',
};

export function locationLabel(result?: IPLocationResult) {
  if (!result) return '归属地解析中…';
  const fields = [...new Set([result.country, result.province, result.city, result.district, result.isp].filter(Boolean))].join(' · ');
  return fields || result.displayName || statusLabels[result.status];
}

/** IP 始终立即展示；归属地单独异步补齐，不改变原有跳转和业务加载状态。 */
export default function SourceIp({ ip, children }: { ip?: string; children?: ReactNode }) {
  const value = ip?.trim() ?? '';
  const subscribe = useCallback((listener: () => void) => ipLocationClient.subscribe(value, listener), [value]);
  const snapshot = useCallback(() => ipLocationClient.getSnapshot(value), [value]);
  const result = useSyncExternalStore(subscribe, snapshot, snapshot);
  if (!value || value === 'unknown') return <>—</>;
  const label = value.length > maxIPLocationInputLength ? '无效 IP 地址' : locationLabel(result);
  return <span style={{ display: 'inline-flex', flexDirection: 'column', gap: 2, whiteSpace: 'normal', overflowWrap: 'anywhere', minWidth: 120 }}>
    <span>{children ?? value}</span>
    <Typography.Text type="secondary" style={{ fontSize: 12, lineHeight: 1.5 }} title={label}>{label}</Typography.Text>
  </span>;
}
