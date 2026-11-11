import { Link } from '@umijs/max';
import { Card, Table, Tag, Typography } from 'antd';
import type { ColumnsType } from 'antd/es/table';
import { useMemo } from 'react';
import SourceIp from '@/components/SourceIp';
import type { AdapterActivity, ThreatIpProfile } from '@/services/honeypot/api';

const numberFormat = new Intl.NumberFormat('zh-CN');
const timeFormat = new Intl.DateTimeFormat('zh-CN', {
  timeZone: 'Asia/Shanghai',
  month: '2-digit',
  day: '2-digit',
  hour: '2-digit',
  minute: '2-digit',
  hourCycle: 'h23',
});
const scoreColors: Record<string, string> = {
  Blocked: 'red',
  Suspicious: 'orange',
};

function renderTime(value: string) {
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp)) return '—';
  return <time dateTime={value}>{timeFormat.format(timestamp)}</time>;
}

const adapterColumns: ColumnsType<AdapterActivity> = [
  {
    title: '协议',
    dataIndex: 'adapterKey',
    width: 60,
    ellipsis: true,
    render: (value: string) =>
      value === 'unknown' ? '未知' : value.toUpperCase(),
  },
  {
    title: '连接',
    dataIndex: 'acceptedConnections',
    width: 52,
    align: 'right',
    render: numberFormat.format,
  },
  {
    title: '认证失败',
    dataIndex: 'authenticationFailures',
    width: 78,
    align: 'right',
    render: numberFormat.format,
  },
  {
    title: '来源 IP 数',
    dataIndex: 'sourceIpCount',
    width: 80,
    align: 'right',
    render: numberFormat.format,
  },
  {
    title: '协议异常',
    dataIndex: 'protocolViolations',
    width: 78,
    align: 'right',
    render: numberFormat.format,
  },
  {
    title: '最近活动',
    dataIndex: 'lastActivityAtUtc',
    width: 100,
    render: renderTime,
  },
];

const riskColumns: ColumnsType<ThreatIpProfile> = [
  {
    title: '来源 IP',
    dataIndex: 'sourceIp',
    width: 170,
    render: (value: string) => (
      <SourceIp ip={value}><Link to={`/events?sourceIp=${encodeURIComponent(value)}`} title={value}>
        {value}
      </Link></SourceIp>
    ),
  },
  {
    title: '风险分',
    dataIndex: 'currentScore',
    width: 60,
    align: 'right',
    render: (value: number, row) => (
      <Tag color={scoreColors[row.status]} style={{ marginInlineEnd: 0 }}>
        {numberFormat.format(value)}
      </Tag>
    ),
  },
  {
    title: '认证尝试',
    dataIndex: 'authenticationAttemptCount',
    width: 78,
    align: 'right',
    render: numberFormat.format,
  },
  {
    title: '服务 / 端口',
    key: 'servicesAndPorts',
    width: 96,
    ellipsis: true,
    render: (_, row) =>
      [
        row.servicesTouched?.join('、').toUpperCase(),
        row.portsTouched?.join('、'),
      ]
        .filter(Boolean)
        .join(' / ') || '—',
  },
  {
    title: '最近出现',
    dataIndex: 'lastSeenUtc',
    width: 100,
    render: renderTime,
  },
];

export function AdapterActivityCard({
  activity,
  loading,
}: {
  activity?: AdapterActivity[];
  loading: boolean;
}) {
  return (
    <Card
      size="small"
      title="协议活动"
      extra={<Typography.Text type="secondary">近 24 小时</Typography.Text>}
      style={{ height: '100%', minWidth: 0 }}
      styles={{ body: { padding: 0 } }}
    >
      <Table
        rowKey="adapterKey"
        size="small"
        loading={loading}
        dataSource={activity ?? []}
        columns={adapterColumns}
        pagination={false}
        scroll={{ x: 448 }}
        locale={{
          emptyText: activity ? '近 24 小时暂无协议活动' : '协议活动数据不可用',
        }}
      />
    </Card>
  );
}

export function RiskSourcesCard({
  threats,
  loading,
}: {
  threats?: ThreatIpProfile[];
  loading: boolean;
}) {
  const topThreats = useMemo(
    () =>
      [...(threats ?? [])]
        .sort(
          (a, b) =>
            b.currentScore - a.currentScore ||
            b.authenticationAttemptCount - a.authenticationAttemptCount ||
            Date.parse(b.lastSeenUtc) - Date.parse(a.lastSeenUtc),
        )
        .slice(0, 5),
    [threats],
  );

  return (
    <Card
      size="small"
      title="优先排查来源"
      extra={<Link to="/threats">查看威胁清单</Link>}
      style={{ height: '100%', minWidth: 0 }}
      styles={{ body: { padding: 0 } }}
    >
      <Table
        rowKey="threatId"
        size="small"
        loading={loading}
        dataSource={topThreats}
        columns={riskColumns}
        pagination={false}
        scroll={{ x: 456 }}
        locale={{
          emptyText: threats ? '暂无待排查来源' : '威胁来源数据不可用',
        }}
      />
    </Card>
  );
}
