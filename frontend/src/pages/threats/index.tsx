import { useIntl } from '@umijs/max';
import { Alert, Card, Empty, Spin, Table, Tag, Typography } from 'antd';
import type { ColumnsType } from 'antd/es/table';
import React, { useCallback, useEffect, useState } from 'react';
import ExcelExportButton from '@/components/ExcelExportButton';
import SourceIp from '@/components/SourceIp';
import { getThreats, normalizePage, type ThreatIpProfile } from '@/services/honeypot/api';
import { connectHoneypotRealtime } from '@/services/realtime';

const statusColors: Record<string, string> = {
  New: 'default',
  Observed: 'blue',
  Suspicious: 'orange',
  Blocked: 'red',
  Allowlisted: 'green',
  Muted: 'purple',
  Expired: 'default',
  unknown: 'default',
};

const statusKey = (status: string) => Object.hasOwn(statusColors, status) ? status : 'unknown';
const formatList = (value: string[] | number[] | undefined) => (value ?? []).join(', ');

const ThreatsPage: React.FC = () => {
  const intl = useIntl();
  const t = (id: string) => intl.formatMessage({ id: `threats.${id}` });
  const statusLabel = (status: string) => t(`status.${statusKey(status)}`);
  const timeLabel = (value: string) => new Date(value).toLocaleString(intl.locale, { timeZone: 'Asia/Shanghai' });
  const [rows, setRows] = useState<ThreatIpProfile[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string>();

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const response = await getThreats();
      setRows(normalizePage(response.data).items);
      setError(undefined);
    } catch (loadError) {
      setError(loadError instanceof Error ? loadError.message : '');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
    let cleanup: (() => Promise<void>) | undefined;
    void connectHoneypotRealtime({
      onEvent: () => void load(),
    })
      .then((dispose) => {
        cleanup = dispose;
      })
      .catch(() => {
        // 实时通道不可用时仍保留 REST 查询。
      });
    return () => {
      void cleanup?.();
    };
  }, [load]);

  const columns = [
    { title: t('sourceIp'), dataIndex: 'sourceIp', width: 180, render: (value: string) => <SourceIp ip={value} /> },
    { title: t('status'), dataIndex: 'status', render: (value: string) => <Tag color={statusColors[statusKey(value)]}>{statusLabel(value)}</Tag> },
    { title: t('currentScore'), dataIndex: 'currentScore' },
    { title: t('maxScore'), dataIndex: 'maxScore' },
    { title: t('attemptCount'), dataIndex: 'attemptCount' },
    { title: t('activeSessionCount'), dataIndex: 'activeSessionCount' },
    { title: t('authenticationAttemptCount'), dataIndex: 'authenticationAttemptCount' },
    { title: t('servicesTouched'), dataIndex: 'servicesTouched', render: (value: string[]) => formatList(value) || '-' },
    { title: t('portsTouched'), dataIndex: 'portsTouched', render: (value: number[]) => formatList(value) || '-' },
    { title: t('lastSeenUtc'), dataIndex: 'lastSeenUtc', render: timeLabel },
  ] satisfies ColumnsType<ThreatIpProfile>;

  return (
    <div>
      <Typography.Title level={3}>{t('title')}</Typography.Title>
      <Typography.Paragraph type="secondary">{t('description')}</Typography.Paragraph>
      {error !== undefined && <Alert title={t('unavailable')} description={error} type="warning" showIcon style={{ marginBottom: 16 }} />}
      <Card extra={
        <ExcelExportButton
          filename={t('title')}
          sheetName={t('title')}
          headers={[
            ...columns.map(({ title }) => title),
            t('threatId'), t('firstSeenUtc'), t('lastEventId'), t('scoreVersion'),
            t('sessionCount'), t('protocolViolationCount'), t('expiresAtUtc'),
          ]}
          rows={() => rows.map((row) => [
            row.sourceIp,
            statusLabel(row.status),
            row.currentScore,
            row.maxScore,
            row.attemptCount,
            row.activeSessionCount,
            row.authenticationAttemptCount,
            formatList(row.servicesTouched),
            formatList(row.portsTouched),
            timeLabel(row.lastSeenUtc),
            row.threatId,
            timeLabel(row.firstSeenUtc),
            row.lastEventId,
            row.scoreVersion,
            row.sessionCount,
            row.protocolViolationCount,
            row.expiresAtUtc ? timeLabel(row.expiresAtUtc) : undefined,
          ])}
          disabled={loading || error !== undefined || rows.length === 0}
        />
      }>
        {loading ? <Spin /> : rows.length === 0 ? <Empty description={t('empty')} /> : <Table rowKey="threatId" dataSource={rows} columns={columns} pagination={{ pageSize: 20 }} scroll={{ x: 1250 }} />}
      </Card>
    </div>
  );
};

export default ThreatsPage;
