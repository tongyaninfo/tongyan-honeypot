import { Line } from '@ant-design/plots';
import { Card, Empty, Typography } from 'antd';
import { useLayoutEffect, useMemo, useRef, useState } from 'react';
import type { ActivityHour } from '@/services/honeypot/api';

const hourTime = new Intl.DateTimeFormat('zh-CN', {
  timeZone: 'Asia/Shanghai', hour: '2-digit', minute: '2-digit', hourCycle: 'h23',
});

const detailTime = new Intl.DateTimeFormat('zh-CN', {
  timeZone: 'Asia/Shanghai', month: '2-digit', day: '2-digit',
  hour: '2-digit', minute: '2-digit', hourCycle: 'h23',
});

const coverageLabels = {
  complete: '采集覆盖完整',
  partial: '采集覆盖不完整',
  unknown: '采集覆盖未知',
};

const connections = { name: '连接', color: '#3b82f6' };
const authenticationFailures = { name: '认证失败', color: '#f87171' };

type HourDatum = Pick<ActivityHour, 'acceptedConnections' | 'authenticationFailures'> & {
  hour: string;
  coverage: string;
};

const hourTooltip = {
  title: ({ hour }: HourDatum) => detailTime.format(new Date(hour)),
  items: [
    ({ acceptedConnections }: HourDatum) => ({ ...connections, value: acceptedConnections ?? '无可用观测' }),
    ({ authenticationFailures: count }: HourDatum) => ({ ...authenticationFailures, value: count ?? '无可用观测' }),
    ({ coverage }: HourDatum) => ({ name: '采集覆盖', color: '#94a3b8', value: coverage }),
  ],
};

export default function OverviewActivityTrend({ hours, loading }: {
  hours?: ActivityHour[];
  loading: boolean;
}) {
  const container = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(0);

  useLayoutEffect(() => {
    const element = container.current;
    if (!element) return;
    // 侧栏展开会改变卡片宽度，但不会触发图表监听的窗口 resize。
    const measure = () => setWidth(Math.floor(element.getBoundingClientRect().width));
    const observer = new ResizeObserver(measure);
    measure();
    observer.observe(element);
    return () => observer.disconnect();
  }, [loading]);

  const { series, observedPoints } = useMemo(() => {
    const series = (hours ?? []).flatMap((item) => {
      const datum: HourDatum = {
        hour: item.key,
        acceptedConnections: item.acceptedConnections,
        authenticationFailures: item.authenticationFailures,
        coverage: item.coverageStatus ? coverageLabels[item.coverageStatus] : '未提供覆盖状态',
      };
      return [
        { ...datum, series: connections.name, count: item.acceptedConnections },
        { ...datum, series: authenticationFailures.name, count: item.authenticationFailures },
      ];
    });
    // 保留空值以断开折线，且只在有观测的位置创建可见散点。
    return { series, observedPoints: series.filter((item) => item.count !== null) };
  }, [hours]);
  const incomplete = hours?.some((item) => item.coverageStatus === 'partial' || item.coverageStatus === 'unknown');

  return (
    <Card size="small" title="近 24 小时连接与认证失败" loading={loading} style={{ height: '100%' }}>
      <div ref={container} style={{ width: '100%', overflow: 'clip' }}>
        {observedPoints.length > 0 ? (
          <>
            {width > 0 && (
              <Line
                autoFit={false}
                width={width}
                height={202}
                data={series}
                xField="hour"
                yField="count"
                colorField="series"
                connectNulls={false}
                point={{ data: observedPoints, sizeField: 3, tooltip: false }}
                // 以小时共享提示，两条折线的同一小时数据去重后只显示一组。
                tooltip={hourTooltip}
                interaction={{ tooltip: { shared: true, crosshairsX: true, crosshairsY: true, marker: false } }}
                scale={{
                  x: { domain: hours?.map((item) => item.key) },
                  color: {
                    domain: [connections.name, authenticationFailures.name],
                    range: [connections.color, authenticationFailures.color],
                  },
                }}
                axis={{
                  x: {
                    title: false,
                    labelAutoRotate: false,
                    labelAutoHide: true,
                    labelFilter: (_: unknown, index: number) => index % 4 === 0,
                    labelFormatter: (value: string) => hourTime.format(new Date(value)),
                  },
                  y: { title: false },
                }}
                legend={{ color: { position: 'top' } }}
                style={{ lineWidth: 2 }}
              />
            )}
            {incomplete && <Typography.Text type="secondary">部分小时采集覆盖不完整。曲线空白处没有可用观测。</Typography.Text>}
          </>
        ) : (
          <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={hours ? '近 24 小时暂无可用观测' : '趋势数据不可用'} />
        )}
      </div>
    </Card>
  );
}
