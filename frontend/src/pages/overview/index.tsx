import { ConfigProvider as PlotConfigProvider, Line } from '@ant-design/plots';
import { Link, useIntl, useModel } from '@umijs/max';
import {
  Alert,
  Card,
  Col,
  Empty,
  Row,
  Space,
  Table,
  Tag,
  Typography,
} from 'antd';
import type { ColumnsType } from 'antd/es/table';
import { createStyles } from 'antd-style';
import React, { useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import SourceIp from '@/components/SourceIp';
import {
  type ApiResult,
  getCredentialEvidenceSummaries,
  getEvents,
  getOverviewMetrics,
  getThreats,
  normalizePage,
  type InteractionEvent,
  type ListenerOverview,
  type OverviewMetrics,
  type ThreatIpProfile,
} from '@/services/honeypot/api';
import { connectHoneypotRealtime } from '@/services/realtime';
import { resolveTheme } from '@/utils/theme';
import { AdapterActivityCard, RiskSourcesCard } from './OverviewActivityTables';
import OverviewHeader from './OverviewHeader';

interface OverviewData {
  metrics: OverviewMetrics;
  metricsAvailable: boolean;
  events: InteractionEvent[];
  threats?: ThreatIpProfile[];
  credentials?: number;
  activityCount?: number;
}

const emptyMetrics: OverviewMetrics = {
  generatedAtUtc: '',
  eventCount: 0,
  acceptedConnections: 0,
  authenticationAttempts: 0,
  authenticationFailures: 0,
  protocolViolations: 0,
  sessionClosed: 0,
  threatIpCount: 0,
  serviceInstanceCount: 0,
  listenerCount: 0,
  runningListenerCount: 0,
  failedListenerCount: 0,
  activeConnections: 0,
  acceptedCount: 0,
  listenerErrorCount: 0,
  eventsByAdapter: [],
  eventsByOutcome: [],
  eventsByHour: [],
  listeners: [],
};

const emptyData: OverviewData = {
  metrics: emptyMetrics,
  metricsAvailable: false,
  events: [],
};

const resultLabels: Record<string, string> = {
  completed: '已完成',
  failure: '失败',
  rejected: '已拒绝',
  observed: '已观察',
  recorded: '已记录',
  sent: '已发送',
  client_closed: '客户端关闭',
};

const eventTime = new Intl.DateTimeFormat('zh-CN', {
  timeZone: 'Asia/Shanghai', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit',
});

const hourTime = new Intl.DateTimeFormat('zh-CN', {
  timeZone: 'Asia/Shanghai', hour: '2-digit', minute: '2-digit', hourCycle: 'h23',
});

const listenerStates: Record<string, { text: string; color: string; order: number }> = {
  failed: { text: '失败', color: 'error', order: 0 },
  running: { text: '运行中', color: 'success', order: 1 },
  starting: { text: '启动中', color: 'processing', order: 2 },
  stopping: { text: '停止中', color: 'warning', order: 3 },
  stopped: { text: '已停止', color: 'default', order: 4 },
};

const listenerColumns: ColumnsType<ListenerOverview> = [
  {
    title: '监听端口',
    width: 106,
    render: (_, row) => <Typography.Text>{row.adapterKey?.toUpperCase() || '—'} · {row.port}</Typography.Text>,
  },
  {
    title: '状态', dataIndex: 'state', width: 80,
    render: (state: string) => {
      const status = listenerStates[state?.toLowerCase()];
      return <Tag color={status?.color}>{status?.text ?? '未知'}</Tag>;
    },
  },
  { title: '活动连接', dataIndex: 'activeConnections', width: 75, align: 'right' },
  { title: '接收数', dataIndex: 'acceptedCount', width: 70, align: 'right' },
];

const readResult = <T,>(result: PromiseSettledResult<ApiResult<T>>) =>
  result.status === 'fulfilled' && result.value.success ? result.value.data : undefined;

async function loadOverview(): Promise<OverviewData> {
  const [metricsResult, eventsResult, threatsResult, evidenceResult] = await Promise.allSettled([
    getOverviewMetrics(),
    getEvents({ view: 'activity', page: 1, pageSize: 50 }),
    getThreats(),
    getCredentialEvidenceSummaries(),
  ]);
  const metrics = readResult(metricsResult);
  const events = readResult(eventsResult);
  const threats = readResult(threatsResult);
  return {
    metrics: metrics ?? emptyMetrics,
    metricsAvailable: Boolean(metrics),
    events: normalizePage(events).items,
    threats: threats ? normalizePage(threats).items : undefined,
    credentials: readResult(evidenceResult)?.total,
    activityCount: events ? normalizePage(events).total : undefined,
  };
}

const emptyChart = (description: string) => <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={description} />;

// 图表独立绘制文字，需要跟随管理台主题。深色下同时提高刻度和连续图例的文字对比度。
const darkChartTheme = {
  type: 'dark' as const,
  axis: { labelOpacity: 0.85 },
  legendContinuous: { titleFill: '#fff', labelFillOpacity: 0.85, handleLabelFillOpacity: 0.85 },
  label: { fillOpacity: 0.9 },
};

const useOverviewStyles = createStyles(({ css, token }, dark: boolean) => ({
  overview: css`
    a {
      color: ${dark ? '#91caff' : token.colorPrimaryTextActive};
      &:hover { text-decoration: underline; }
    }
  `,
}));

const OverviewPage: React.FC = () => {
  const intl = useIntl();
  const { initialState } = useModel('@@initialState');
  const dark = resolveTheme(initialState?.themeMode ?? 'light') === 'realDark';
  const chartTheme = dark ? darkChartTheme : 'light';
  const { styles } = useOverviewStyles(dark);
  const [data, setData] = useState<OverviewData>(emptyData);
  const [loading, setLoading] = useState(true);
  const trendContainer = useRef<HTMLDivElement>(null);
  const [trendWidth, setTrendWidth] = useState(0);

  useLayoutEffect(() => {
    const container = trendContainer.current;
    if (!container) return;
    // 侧栏展开会改变卡片宽度，但不会触发图表监听的窗口 resize。
    const measure = () => setTrendWidth(Math.floor(container.getBoundingClientRect().width));
    const observer = new ResizeObserver(measure);
    measure();
    observer.observe(container);
    return () => observer.disconnect();
  }, [loading]);

  useEffect(() => {
    let disposed = false;
    let refreshing = false;
    let refreshQueued = false;
    let cleanup: (() => Promise<void>) | undefined;

    const refresh = async () => {
      if (disposed) return;
      // 批量实时消息只合并为一次后续请求，页面保留上次快照以便连续阅读。
      if (refreshing) {
        refreshQueued = true;
        return;
      }
      refreshing = true;
      try {
        do {
          refreshQueued = false;
          const snapshot = await loadOverview();
          if (!disposed) {
            setData(snapshot);
            setLoading(false);
          }
        } while (refreshQueued && !disposed);
      } finally {
        refreshing = false;
      }
    };

    void refresh();
    void connectHoneypotRealtime({
      onEvent: () => void refresh(),
      onRuntime: () => void refresh(),
    })
      .then((dispose) => {
        if (disposed) void dispose();
        else cleanup = dispose;
      })
      .catch(() => {
        // 页面首次加载和断线期间仍可使用 REST 快照。
      });
    return () => {
      disposed = true;
      void cleanup?.();
    };
  }, []);

  const { metrics } = data;
  const listenerRows = useMemo(
    () => [...metrics.listeners].sort((left, right) =>
      (listenerStates[left.state?.toLowerCase()]?.order ?? 5) - (listenerStates[right.state?.toLowerCase()]?.order ?? 5)
      || left.port - right.port,
    ).slice(0, 5),
    [metrics.listeners],
  );

  const timelineData = useMemo(
    () => (metrics.activityByHour ?? []).flatMap((item) => [
      { hour: hourTime.format(new Date(item.key)), series: '连接', count: item.acceptedConnections },
      { hour: hourTime.format(new Date(item.key)), series: '认证失败', count: item.authenticationFailures },
    ]),
    [metrics.activityByHour],
  );

  const recentEvents = useMemo(
    () => [...data.events].sort((a, b) => new Date(b.occurredAtUtc).getTime() - new Date(a.occurredAtUtc).getTime()).slice(0, 8),
    [data.events],
  );

  const eventColumns: ColumnsType<InteractionEvent> = [
    { title: '时间', dataIndex: 'occurredAtUtc', render: (value: string) => eventTime.format(new Date(value)), width: 106 },
    { title: '来源 IP', dataIndex: 'sourceIp', width: 180, render: (value: string) => <SourceIp ip={value}><Link to={`/events?sourceIp=${encodeURIComponent(value)}`}>{value}</Link></SourceIp> },
    { title: '协议 / 端口', width: 115, render: (_, row) => `${row.adapterKey?.toUpperCase() || '—'} · ${row.destinationPort}` },
    { title: intl.formatMessage({ id: 'events.event' }), dataIndex: 'eventType', width: 118, render: (value: string) => intl.formatMessage({ id: `events.type.${value}`, defaultMessage: intl.formatMessage({ id: 'events.unknown' }) }) },
    { title: '结果', dataIndex: 'outcome', width: 68, render: (value: string) => resultLabels[value] ?? value ?? '—' },
    { title: '认证方式', dataIndex: 'authenticationMethod', width: 112, ellipsis: true, render: (value?: string) => value || '—' },
    { title: '失败码', dataIndex: 'authenticationFailureCode', width: 174, ellipsis: true, render: (value?: string) => value || '—' },
  ];

  return (
    <PlotConfigProvider common={{ theme: chartTheme }}>
      <Space orientation="vertical" size="middle" className={styles.overview} style={{ display: 'flex' }}>
        <OverviewHeader
          metrics={metrics}
          metricsAvailable={data.metricsAvailable}
          loading={loading && !data.metricsAvailable}
          credentialCount={data.credentials}
        />
        {!loading && !data.metricsAvailable && <Alert title="运行指标暂不可用" type="warning" showIcon />}
        <Row gutter={[16, 16]}>
          <Col xs={24} xl={12}>
            <AdapterActivityCard activity={metrics.adapterActivity} loading={loading} />
          </Col>
          <Col xs={24} xl={12}>
            <RiskSourcesCard threats={data.threats} loading={loading} />
          </Col>
          <Col xs={24} lg={14}>
            <Card size="small" title="近 24 小时连接与认证失败" loading={loading} style={{ height: '100%' }}>
              <div ref={trendContainer} style={{ width: '100%', overflow: 'clip' }}>
                {timelineData.some((item) => item.count > 0) ? (trendWidth > 0 && (
                  <Line
                    autoFit={false}
                    width={trendWidth}
                    height={202}
                    data={timelineData}
                    xField="hour"
                    yField="count"
                    colorField="series"
                    scale={{ color: { domain: ['连接', '认证失败'], range: ['#3b82f6', '#f87171'] } }}
                    axis={{
                      x: {
                        title: false,
                        labelAutoRotate: false,
                        labelAutoHide: true,
                        labelFilter: (_: unknown, index: number) => index % 4 === 0,
                      },
                      y: { title: false },
                    }}
                    legend={{ color: { position: 'top' } }}
                    style={{ lineWidth: 2 }}
                  />
                )) : emptyChart(metrics.activityByHour ? '近 24 小时暂无连接或认证失败' : '趋势数据不可用')}
              </div>
            </Card>
          </Col>
          <Col xs={24} lg={10}>
            <Card
              size="small"
              title="监听器运行状态"
              extra={<Link to="/services">查看服务实例</Link>}
              style={{ height: '100%' }}
              styles={{ body: { padding: 0 } }}
            >
              <Table
                rowKey="listenerId"
                size="small"
                loading={loading}
                pagination={false}
                columns={listenerColumns}
                dataSource={listenerRows}
                scroll={{ x: 331 }}
                locale={{ emptyText: data.metricsAvailable ? '暂无监听器' : '监听器数据不可用' }}
              />
            </Card>
          </Col>
        </Row>
        <Card
          size="small"
          title="最近事件"
          extra={<Space size="middle">
            {data.activityCount !== undefined && <Typography.Text type="secondary">共 {data.activityCount} 条</Typography.Text>}
            <Link to="/events">查看全部事件</Link>
          </Space>}
          styles={{ body: { padding: 0 } }}
        >
          <Table
            rowKey="eventId"
            size="small"
            loading={loading}
            pagination={false}
            columns={eventColumns}
            dataSource={recentEvents}
            scroll={{ x: 836 }}
            locale={{ emptyText: data.activityCount === undefined ? '事件数据不可用' : '暂无事件' }}
          />
        </Card>
      </Space>
    </PlotConfigProvider>
  );
};

export default OverviewPage;
