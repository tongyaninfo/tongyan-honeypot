import { Link } from '@umijs/max';
import { Button, Card, Modal, Table, Tag, Typography } from 'antd';
import type { ColumnsType } from 'antd/es/table';
import { useMemo, useState } from 'react';
import SourceIp from '@/components/SourceIp';
import type {
  AdapterActivity,
  OverviewAdapterActivityFilter,
  OverviewAdapterActivityMetric,
  ThreatIpProfile,
} from '@/services/honeypot/api';
import { OverviewConnectionsDetails } from './OverviewConnectionsPopover';

export const RISK_SOURCE_LIMIT = 8;

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

const metricLabels: Record<OverviewAdapterActivityMetric, string> = {
  acceptedConnections: '连接',
  authenticationFailures: '认证失败',
  sourceIpCount: '来源 IP',
  protocolViolations: '协议异常',
};

function adapterName(adapter: string) {
  return adapter === 'unknown' ? '未知' : adapter.toUpperCase();
}

function activityDetailTitle(adapter: string, metric: OverviewAdapterActivityMetric) {
  const detail = metric === 'sourceIpCount' ? '来源 IP 明细' : `${metricLabels[metric]}明细`;
  return `${adapterName(adapter)} ${detail}`;
}

function adapterColumns(
  openDetails: (filter: OverviewAdapterActivityFilter) => void,
): ColumnsType<AdapterActivity> {
  const metricColumn = (
    dataIndex: OverviewAdapterActivityMetric,
    width: number,
  ): ColumnsType<AdapterActivity>[number] => ({
    title: dataIndex === 'sourceIpCount' ? '来源 IP 数' : metricLabels[dataIndex],
    dataIndex,
    width,
    align: 'right',
    render: (value: number, row) => {
      const displayed = numberFormat.format(value);
      return value > 0 ? (
        <Button
          size="small"
          type="link"
          style={{ paddingInline: 0 }}
          aria-label={`${activityDetailTitle(row.adapterKey, dataIndex)}，${displayed}`}
          aria-haspopup="dialog"
          onClick={() =>
            openDetails({ scope: 'adapterActivity', adapterKey: row.adapterKey, metric: dataIndex })
          }
        >
          {displayed}
        </Button>
      ) : displayed;
    },
  });
  return [
    {
      title: '协议',
      dataIndex: 'adapterKey',
      width: 60,
      ellipsis: true,
      render: adapterName,
    },
    metricColumn('acceptedConnections', 52),
    metricColumn('authenticationFailures', 78),
    metricColumn('sourceIpCount', 80),
    metricColumn('protocolViolations', 78),
    {
      title: '最近活动',
      dataIndex: 'lastActivityAtUtc',
      width: 100,
      render: renderTime,
    },
  ];
}

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
  asOfUtc,
}: {
  activity?: AdapterActivity[];
  loading: boolean;
  asOfUtc?: string;
}) {
  const [selected, setSelected] = useState<OverviewAdapterActivityFilter>();
  const wide = selected?.metric === 'authenticationFailures' || selected?.metric === 'protocolViolations';
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
        columns={adapterColumns((filter) => setSelected(asOfUtc ? { ...filter, asOfUtc } : filter))}
        pagination={false}
        scroll={{ x: 448 }}
        locale={{
          emptyText: activity ? '近 24 小时暂无协议活动' : '协议活动数据不可用',
        }}
      />
      <Modal
        open={!!selected}
        title={selected ? activityDetailTitle(selected.adapterKey, selected.metric) : undefined}
        onCancel={() => setSelected(undefined)}
        footer={null}
        destroyOnHidden
        width={wide ? 860 : 700}
      >
        {selected && <OverviewConnectionsDetails filter={selected} />}
      </Modal>
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
        .slice(0, RISK_SOURCE_LIMIT),
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
