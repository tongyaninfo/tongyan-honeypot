import { useIntl } from '@umijs/max';
import { Alert, Card, Empty, Spin, Table, Tag, Typography } from 'antd';
import type { ColumnsType } from 'antd/es/table';
import React, { useCallback, useEffect, useRef, useState } from 'react';
import ExcelExportButton from '@/components/ExcelExportButton';
import SourceIp from '@/components/SourceIp';
import { getThreats, loadExportRows, normalizePage, pageFromResponse, type PageResult, type ThreatIpProfile } from '@/services/honeypot/api';
import { useRealtimeRefresh } from '@/hooks/useRealtimeRefresh';

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
  const [snapshot, setSnapshot] = useState<PageResult<ThreatIpProfile>>(() => normalizePage(undefined));
  const { items: rows, total } = snapshot;
  const [page, setPage] = useState(1);
  const requestId = useRef(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string>();

  const load = useCallback(async () => {
    const id = ++requestId.current;
    setLoading(true);
    try {
      const response = await getThreats({ page, pageSize: 20 });
      if (requestId.current !== id) return;
      const result = pageFromResponse(response);
      if (page > 1 && result.items.length === 0) setPage(Math.max(1, Math.ceil(result.total / 20)));
      setSnapshot(result);
      setError(undefined);
    } catch (loadError) {
      if (requestId.current === id) setError(loadError instanceof Error ? loadError.message : '');
    } finally {
      if (requestId.current === id) setLoading(false);
    }
  }, [page]);

  useEffect(() => {
    void load();
    return () => { requestId.current++; };
  }, [load]);
  useRealtimeRefresh(load);

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
      <Card extra={
        <ExcelExportButton
          filename={t('title')}
          sheetName={t('title')}
          headers={[
            ...columns.map(({ title }) => title),
            t('threatId'), t('firstSeenUtc'), t('lastEventId'), t('scoreVersion'),
            t('sessionCount'), t('protocolViolationCount'), t('expiresAtUtc'),
          ]}
          prepare={async () => {
            const items = await loadExportRows(getThreats, (row) => row.threatId, snapshot);
            return { additionalSheets: [], rows: items.map((row) => [
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
            ]) };
          }}
          disabled={loading || error !== undefined || rows.length === 0}
        />
      }>
        {error !== undefined && <Alert title={t('unavailable')} description={error} type="warning" showIcon style={{ marginBottom: 16 }} />}
        {loading && rows.length === 0 && <Spin />}
        {!loading && error === undefined && rows.length === 0 && <Empty description={t('empty')} />}
        {rows.length > 0 && <Table rowKey="threatId" loading={loading} dataSource={rows} columns={columns} pagination={{ current: page, pageSize: 20, total, showSizeChanger: false, onChange: setPage }} scroll={{ x: 1250 }} />}
      </Card>
    </div>
  );
};

export default ThreatsPage;
