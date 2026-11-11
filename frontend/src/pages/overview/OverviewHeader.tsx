import {
  ApiOutlined,
  ClockCircleOutlined,
  DesktopOutlined,
  GlobalOutlined,
  LaptopOutlined,
  RadarChartOutlined,
  SafetyCertificateOutlined,
  WarningOutlined,
} from '@ant-design/icons';
import { Breadcrumb, Card, Tooltip, Typography } from 'antd';
import { createStyles } from 'antd-style';
import type { ReactNode } from 'react';
import type { OverviewMetrics } from '@/services/honeypot/api';

const useStyles = createStyles(({ token, css }) => ({
  header: css`
    display: grid;
    gap: ${token.marginLG}px;
    min-width: 0;
  `,
  intro: css`
    display: grid;
    gap: ${token.marginSM}px;
  `,
  cards: css`
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1.15fr)) repeat(2, minmax(0, 1fr));
    gap: ${token.marginLG}px;
    @media (max-width: ${token.screenXL - 1}px) {
      grid-template-columns: repeat(2, minmax(0, 1fr));
    }
    @media (max-width: ${token.screenSM - 1}px) {
      grid-template-columns: minmax(0, 1fr);
      gap: ${token.marginSM}px;
    }
  `,
  metricCard: css`
    min-width: 0;
    min-height: 148px;
    @media (max-width: ${token.screenSM - 1}px) {
      min-height: 0;
    }
  `,
  connectionMetrics: css`
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    column-gap: ${token.marginXS}px;
    > div > span:first-child {
      font-size: ${token.fontSize}px;
      gap: ${token.marginXXS}px;
      white-space: nowrap;
    }
  `,
  label: css`
    display: flex;
    align-items: center;
    gap: ${token.marginXS}px;
    color: ${token.colorTextSecondary};
    font-size: ${token.fontSizeLG}px;
  `,
  value: css`
    display: block;
    margin-top: ${token.marginXS}px;
    font-size: ${token.fontSizeHeading2}px;
    line-height: ${token.lineHeightHeading2};
    color: ${token.colorTextHeading};
    font-weight: 600;
    font-variant-numeric: tabular-nums;
    overflow-wrap: anywhere;
  `,
  status: css`
    display: block;
    margin-top: ${token.marginXS}px;
    font-size: ${token.fontSizeLG}px;
    color: ${token.colorTextHeading};
    font-weight: 600;
  `,
  hint: css`
    display: block;
    margin-top: ${token.marginXXS}px;
    color: ${token.colorTextSecondary};
  `,
  hostGrid: css`
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: ${token.marginLG}px;
    margin: 0;
    @media (max-width: ${token.screenXL - 1}px) {
      grid-template-columns: repeat(2, minmax(0, 1fr));
    }
    @media (max-width: ${token.screenSM - 1}px) {
      grid-template-columns: minmax(0, 1fr);
      gap: ${token.marginSM}px;
    }
  `,
  hostField: css`
    min-width: 0;
    dd {
      margin: ${token.marginXS}px 0 0;
      min-width: 0;
    }
  `,
  hostValue: css`
    display: block;
    width: 100%;
    font-size: ${token.fontSizeLG}px;
    color: ${token.colorTextHeading};
  `,
  addresses: css`
    cursor: help;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  `,
}));

const numberFormat = new Intl.NumberFormat('zh-CN');
const bootTimeFormat = new Intl.DateTimeFormat('zh-CN', {
  timeZone: 'Asia/Shanghai',
  year: 'numeric',
  month: '2-digit',
  day: '2-digit',
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
  hourCycle: 'h23',
});

const formatCount = (value?: number) =>
  value != null && Number.isFinite(value) ? numberFormat.format(value) : '—';

const formatBootTime = (value?: string | null) => {
  const timestamp = value ? Date.parse(value) : Number.NaN;
  return Number.isFinite(timestamp) ? bootTimeFormat.format(timestamp) : '—';
};

interface OverviewHeaderProps {
  metrics: OverviewMetrics;
  loading: boolean;
  metricsAvailable: boolean;
  credentialCount?: number;
}

export default function OverviewHeader({
  metrics,
  loading,
  metricsAvailable,
  credentialCount,
}: OverviewHeaderProps) {
  const { styles, theme, cx } = useStyles();
  const snapshot = metricsAvailable ? metrics : undefined;
  const label = (icon: ReactNode, text: string) => (
    <span className={styles.label}>
      {icon}
      {text}
    </span>
  );
  const host = snapshot?.host;
  const addresses = host?.ipAddresses ?? [];

  let status = loading ? '加载中…' : '—';
  let statusColor = theme.colorTextSecondary;
  if (snapshot) {
    if (snapshot.failedListenerCount > 0) {
      status = '监听存在异常';
      statusColor = theme.colorError;
    } else if (snapshot.runningListenerCount > 0) {
      const allRunning = snapshot.runningListenerCount === snapshot.listenerCount;
      status = allRunning ? '监听运行正常' : '部分监听运行';
      statusColor = allRunning ? theme.colorSuccess : theme.colorWarning;
    } else {
      status = snapshot.listenerCount > 0 ? '监听器未运行' : '暂无监听器';
    }
  }

  return (
    <section
      className={styles.header}
      aria-label="运行总览"
      aria-busy={loading}
    >
      <Breadcrumb items={[{ title: '管理台' }, { title: '运行总览' }]} />
      <div className={styles.intro}>
        <Typography.Title level={3} style={{ margin: 0 }}>
          运行总览
        </Typography.Title>
        <Typography.Text type="secondary">
          查看蜜罐运行状态、连接活动和近期风险。
        </Typography.Text>
      </div>
      <div className={styles.cards}>
        <Card className={styles.metricCard}>
          {label(
            <SafetyCertificateOutlined
              aria-hidden
              style={{ color: statusColor }}
            />,
            '蜜罐监听状态',
          )}
          <span className={styles.status}>{status}</span>
          <span className={styles.hint}>
            运行中 {formatCount(snapshot?.runningListenerCount)} /{' '}
            {formatCount(snapshot?.listenerCount)} · 服务实例{' '}
            {formatCount(snapshot?.serviceInstanceCount)}
          </span>
        </Card>
        <Card className={styles.metricCard}>
          <div className={styles.connectionMetrics}>
            <div>
              {label(
                <ApiOutlined aria-hidden style={{ color: theme.colorInfo }} />,
                '活动连接',
              )}
              <span className={styles.value}>
                {formatCount(snapshot?.activeConnections)}
              </span>
            </div>
            <div>
              {label(
                <DesktopOutlined
                  aria-hidden
                  style={{ color: theme.colorInfo }}
                />,
                '连接总数',
              )}
              <span className={styles.value}>
                {formatCount(snapshot?.acceptedConnections)}
              </span>
            </div>
          </div>
        </Card>
        <Card className={styles.metricCard}>
          {label(
            <WarningOutlined aria-hidden style={{ color: theme.colorError }} />,
            '今日认证失败',
          )}
          <span className={styles.value}>
            {formatCount(snapshot?.todayAuthenticationFailures)}
          </span>
        </Card>
        <Card className={styles.metricCard}>
          {label(
            <RadarChartOutlined
              aria-hidden
              style={{ color: theme.colorWarning }}
            />,
            '威胁 IP',
          )}
          <span className={styles.value}>
            {formatCount(snapshot?.threatIpCount)}
          </span>
          <span className={styles.hint}>
            认证证据 {formatCount(credentialCount)}
          </span>
        </Card>
      </div>
      <Card>
        <dl className={styles.hostGrid}>
          <div className={styles.hostField}>
            <dt>{label(<LaptopOutlined aria-hidden />, '操作系统版本')}</dt>
            <dd>
              <Typography.Text
                strong
                className={styles.hostValue}
                ellipsis={{ tooltip: host?.osVersion }}
              >
                {host?.osVersion || '—'}
              </Typography.Text>
            </dd>
          </div>
          <div className={styles.hostField}>
            <dt>{label(<DesktopOutlined aria-hidden />, '计算机名称')}</dt>
            <dd>
              <Typography.Text
                strong
                className={styles.hostValue}
                ellipsis={{ tooltip: host?.hostName }}
              >
                {host?.hostName || '—'}
              </Typography.Text>
            </dd>
          </div>
          <div className={styles.hostField}>
            <dt>{label(<GlobalOutlined aria-hidden />, 'IP 地址')}</dt>
            <dd>
              {addresses.length ? (
                <Tooltip
                  title={addresses.map((address) => (
                    <div key={address}>{address}</div>
                  ))}
                  trigger={['hover', 'focus']}
                >
                  <Typography.Text
                    strong
                    tabIndex={0}
                    className={cx(styles.hostValue, styles.addresses)}
                  >
                    {addresses.join(' · ')}
                  </Typography.Text>
                </Tooltip>
              ) : (
                <Typography.Text strong className={styles.hostValue}>
                  —
                </Typography.Text>
              )}
            </dd>
          </div>
          <div className={styles.hostField}>
            <dt>
              {label(<ClockCircleOutlined aria-hidden />, '系统启动时间')}
            </dt>
            <dd>
              <Typography.Text strong className={styles.hostValue}>
                {formatBootTime(host?.bootTimeUtc)}
              </Typography.Text>
            </dd>
          </div>
        </dl>
      </Card>
    </section>
  );
}
