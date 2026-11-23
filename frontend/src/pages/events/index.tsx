import { useAccess, useIntl, useLocation } from '@umijs/max';
import { Alert, Button, Card, Descriptions, Empty, Input, Modal, Select, Space, Spin, Table, Tag, Typography } from 'antd';
import type { ColumnsType } from 'antd/es/table';
import React, { useCallback, useEffect, useRef, useState } from 'react';
import CredentialEvidenceModal, { type CredentialEvidenceTarget } from '@/components/CredentialEvidenceModal';
import ExcelExportButton from '@/components/ExcelExportButton';
import SourceIp from '@/components/SourceIp';
import { getConnectionEvents, getEvents, loadExportRows, normalizePage, pageFromResponse, type InteractionEvent, type PageResult } from '@/services/honeypot/api';
import { useRealtimeRefresh } from '@/hooks/useRealtimeRefresh';

const outcomeColors: Record<string, string> = {
  completed: 'green', failure: 'red', rejected: 'red', admission_rejected: 'red', invalid: 'orange',
  observed: 'blue', sent: 'cyan', recorded: 'green', client_closed: 'default',
  unsupported: 'orange', timeout: 'orange', malformed: 'orange', storage_failed: 'red',
};

const eventTypes = [
  'AuthenticationAttempted', 'AuthorizationDenied', 'AuthenticationRequired', 'HandshakeTimeout',
  'ConnectionAccepted', 'ConnectionRejected', 'ProtocolViolation', 'ResourceLimitExceeded', 'CredentialCaptureFailed',
];

const protocolFailureStages = new Map([
  ['TDS_PRELOGIN_INVALID', 'prelogin'],
  ['TDS_TLS_FAILED', 'tls'],
  ['TDS_LOGIN7_INVALID', 'login'],
  ['TDS_INTEGRATED_AUTH_INVALID', 'integrated'],
]);

const EventActivityList: React.FC<{ initialSourceIp: string; initialEventType?: string }> = ({ initialSourceIp, initialEventType }) => {
  const intl = useIntl();
  const access = useAccess();
  const t = (id: string) => intl.formatMessage({ id: `events.${id}` });
  const message = (id: string) => intl.formatMessage({ id });
  const eventLabel = (type: string) => intl.formatMessage({ id: `events.type.${type}`, defaultMessage: t('unknown') });
  const timeLabel = (value: string) => new Date(value).toLocaleString(intl.locale, { timeZone: 'Asia/Shanghai' });
  const accountLabel = (record: InteractionEvent) => record.username ? `${record.domain ? `${record.domain}\\` : ''}${record.username}` : t('noAccount');
  const outcomeLabel = (value: string) => intl.formatMessage({ id: `events.outcome.${value.toLowerCase()}`, defaultMessage: t('unknown') });
  const materialLabel = (record: InteractionEvent) => {
    if (record.credentialArtifactId)
      return `${intl.formatMessage({ id: `events.material.${record.materialType}`, defaultMessage: t('material.unknown') })} · ${t('capture.saved')}`;
    if (record.credentialCaptureStatus === 'Failed')
      return [t('capture.failed'), record.credentialCaptureError, record.credentialMaterialBytes == null ? null :
        intl.formatMessage({ id: 'events.capture.bytes' }, { count: record.credentialMaterialBytes })].filter(Boolean).join(' · ');
    return t(record.credentialCaptureStatus === 'Disabled' ? 'capture.disabled' : 'capture.none');
  };
  const [snapshot, setSnapshot] = useState<{ result: PageResult<InteractionEvent>; sourceIp: string; eventType?: string }>({ result: normalizePage(undefined), sourceIp: '' });
  const { items: rows, total } = snapshot.result;
  const [page, setPage] = useState(1);
  const requestId = useRef(0);
  const [sourceIp, setSourceIp] = useState(initialSourceIp);
  const [eventType, setEventType] = useState(initialEventType);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [evidenceTarget, setEvidenceTarget] = useState<CredentialEvidenceTarget | null>(null);
  const [connection, setConnection] = useState<InteractionEvent | null>(null);
  const [steps, setSteps] = useState<InteractionEvent[]>([]);
  const [stepsLoading, setStepsLoading] = useState(false);
  const [stepsError, setStepsError] = useState(false);

  const load = useCallback(async () => {
    const currentRequest = ++requestId.current;
    setLoading(true);
    try {
      const response = await getEvents({ sourceIp, eventType, view: 'activity', page, pageSize: 20 });
      if (requestId.current !== currentRequest) return;
      const result = pageFromResponse(response);
      if (page > 1 && result.items.length === 0) setPage(Math.max(1, Math.ceil(result.total / 20)));
      setSnapshot({ result, sourceIp, eventType });
      setError(false);
    } catch {
      if (requestId.current === currentRequest) setError(true);
    } finally {
      if (requestId.current === currentRequest) setLoading(false);
    }
  }, [eventType, page, sourceIp]);

  useEffect(() => {
    void load();
    return () => { requestId.current++; };
  }, [load]);
  useRealtimeRefresh(load);

  useEffect(() => {
    let active = true;
    setSteps([]);
    setStepsError(false);
    setStepsLoading(Boolean(connection));
    if (connection) {
      void getConnectionEvents(connection.connectionId)
        .then((response) => {
          if (!active) return;
          if (response.success) setSteps(normalizePage(response.data).items);
          else setStepsError(true);
        })
        .catch(() => { if (active) setStepsError(true); })
        .finally(() => { if (active) setStepsLoading(false); });
    }
    return () => { active = false; };
  }, [connection]);

  const showEvidence = (record: InteractionEvent) => {
    if (record.credentialArtifactId) setEvidenceTarget({ artifactId: record.credentialArtifactId, adapterKey: record.adapterKey });
  };
  const materialCell = (record: InteractionEvent) => {
    if (!record.credentialArtifactId) return materialLabel(record);
    return <Space orientation="vertical" size={0}>
      <Typography.Text type="secondary">{materialLabel(record)}</Typography.Text>
      {access.canAdmin ? <Button type="link" size="small" style={{ paddingInline: 0 }} onClick={() => showEvidence(record)}>{t('evidence.view')}</Button> : <Typography.Text type="secondary">{t('evidence.adminOnly')}</Typography.Text>}
    </Space>;
  };
  const resultCell = (value?: string) => value ? <Tag color={outcomeColors[value.toLowerCase()] ?? 'default'}>{outcomeLabel(value)}</Tag> : '-';
  const stepSummary = (record: InteractionEvent) => {
    if (record.payloadSummary && (record.eventType === 'ConnectionRejected' || record.outcome === 'admission_rejected'))
      return intl.formatMessage({ id: `events.admission.${record.payloadSummary}`, defaultMessage: record.payloadSummary });
    const code = record.protocolErrorCode;
    const stage = record.adapterKey?.toLowerCase() === 'mssql' && code ? protocolFailureStages.get(code) : undefined;
    if (!stage) return record.payloadSummary;

    // 固定错误码决定显示内容，诊断行不输出任何自由文本或认证报文。
    return <Space orientation="vertical" size={2}>
      <Space size={6}>
        <Typography.Text type="secondary">{t('protocolFailure.stage')}</Typography.Text>
        <Typography.Text>{t(`protocolFailure.${stage}`)}</Typography.Text>
      </Space>
      <Space size={6}>
        <Typography.Text type="secondary">{t('protocolFailure.code')}</Typography.Text>
        <Typography.Text code>{code}</Typography.Text>
      </Space>
    </Space>;
  };

  const exportHeaders = [
    'events.time', 'events.event', 'events.sourceIp', 'excel.sourcePort', 'excel.destinationIp', 'events.port',
    'events.service', 'events.instance', 'events.account', 'events.domain', 'events.database', 'events.method',
    'events.failureCode', 'events.attempt', 'events.material', 'events.evidence.id', 'events.result', 'events.stage',
    'events.risk', 'credentials.eventId', 'excel.connectionId', 'excel.sequence',
  ].map(message);
  const exportRow = (row: InteractionEvent) => [
    timeLabel(row.occurredAtUtc), eventLabel(row.eventType), row.sourceIp, row.sourcePort, row.destinationIp, row.destinationPort,
    row.adapterKey, row.serviceInstanceId, row.username, row.domain, row.database, row.authenticationMethod,
    row.authenticationFailureCode, row.authenticationAttempt, materialLabel(row), row.credentialArtifactId,
    row.outcome ? outcomeLabel(row.outcome) : undefined, row.stage, row.riskDelta, row.eventId, row.connectionId, row.sequence,
  ];

  const columns: ColumnsType<InteractionEvent> = [
    { title: t('time'), dataIndex: 'occurredAtUtc', width: 180, render: timeLabel },
    { title: t('event'), dataIndex: 'eventType', width: 130, render: (value) => <Tag>{eventLabel(value)}</Tag> },
    { title: t('sourceIp'), dataIndex: 'sourceIp', width: 180, render: (value: string) => <SourceIp ip={value} /> },
    { title: t('port'), dataIndex: 'destinationPort', width: 95 },
    { title: t('service'), dataIndex: 'adapterKey', width: 90 },
    { title: t('account'), width: 190, render: (_, record) => accountLabel(record) },
    { title: t('method'), dataIndex: 'authenticationMethod', width: 170, render: (value) => value || '-' },
    { title: t('failureCode'), dataIndex: 'authenticationFailureCode', width: 200, render: (value) => value || '-' },
    { title: t('attempt'), dataIndex: 'authenticationAttempt', width: 100, render: (value) => value ?? '-' },
    { title: t('material'), width: 220, render: (_, record) => materialCell(record) },
    { title: t('result'), dataIndex: 'outcome', width: 110, render: resultCell },
    { title: t('details'), width: 130, fixed: 'right', render: (_, record) => <Button type="link" onClick={() => setConnection(record)}>{intl.formatMessage({ id: 'events.steps' }, { count: record.eventCount ?? 1 })}</Button> },
  ];

  return (
    <div>
      <Typography.Title level={3}>{t('title')}</Typography.Title>
      <Typography.Paragraph type="secondary">{t('grouping')}</Typography.Paragraph>
      <Space wrap style={{ marginBottom: 16 }}>
        <Input placeholder={t('sourceIp')} value={sourceIp} onChange={(event) => { setSourceIp(event.target.value); setPage(1); }} onPressEnter={() => void load()} />
        <Select allowClear placeholder={t('type')} style={{ width: 190 }} value={eventType} onChange={(value) => { setEventType(value); setPage(1); }} options={eventTypes.map((type) => ({ value: type, label: eventLabel(type) }))} />
        <Button type="primary" onClick={() => void load()}>{t('query')}</Button>
        <ExcelExportButton
          filename="threat-events" sheetName={t('title')}
          disabled={loading || error || rows.length === 0 || snapshot.sourceIp !== sourceIp || snapshot.eventType !== eventType}
          headers={exportHeaders}
          prepare={async () => {
            const activities = await loadExportRows(
              (query) => getEvents({ ...query, sourceIp, eventType, view: 'activity' }),
              (row) => row.eventId,
              snapshot.result,
            );
            // 步骤表只收录命中当前行为筛选的连接；原始证据仍走单独的管理员导出。
            const ids = [...new Set(activities.map((row) => row.connectionId))].sort();
            const details: InteractionEvent[] = [];
            for (let offset = 0; offset < ids.length; offset += 32) {
              const batch = new Set(ids.slice(offset, offset + 32));
              const items = await loadExportRows(
                (query) => getEvents({ ...query, sourceIp, view: 'raw', connectionIds: [...batch].join(',') }),
                (row) => row.eventId,
              );
              details.push(...items.filter((row) => batch.has(row.connectionId)));
            }
            details.sort((left, right) => left.connectionId.localeCompare(right.connectionId) || left.sequence - right.sequence);
            return {
              rows: activities.map(exportRow),
              additionalSheets: [{ name: t('details'), headers: exportHeaders, rows: details.map(exportRow) }],
            };
          }}
        />
      </Space>
      <Card>
        {error && <Alert title={t('unavailable')} type="warning" showIcon style={{ marginBottom: 16 }} />}
        {loading && rows.length === 0 && <Spin />}
        {!loading && !error && rows.length === 0 && <Empty description={t('empty')} />}
        {rows.length > 0 && <Table rowKey="eventId" loading={loading} dataSource={rows} columns={columns} pagination={{ current: page, pageSize: 20, total, showSizeChanger: false, onChange: setPage }} scroll={{ x: 1860 }} />}
      </Card>
      <Modal title={t('details')} open={Boolean(connection)} onCancel={() => setConnection(null)} footer={null} width={1000} destroyOnHidden>
        {connection && <Descriptions column={2} size="small" items={[
          { key: 'sourceIp', label: t('sourceIp'), children: <SourceIp ip={connection.sourceIp} /> },
          { key: 'instance', label: t('instance'), children: connection.serviceInstanceId },
          { key: 'account', label: t('account'), children: connection.username || t('noAccount') },
          { key: 'domain', label: t('domain'), children: connection.domain || '-' },
          { key: 'database', label: t('database'), children: connection.database || '-' },
          { key: 'method', label: t('method'), children: connection.authenticationMethod || '-' },
          { key: 'failure', label: t('failureCode'), children: connection.authenticationFailureCode || '-' },
          { key: 'material', label: t('material'), children: materialCell(connection), span: 2 },
        ]} />}
        {stepsError && <Alert title={t('unavailable')} type="warning" />}
        {connection && !stepsLoading && !stepsError && <Space orientation="vertical" size={2} style={{ marginBlock: 12 }}>
          <Typography.Text>{intl.formatMessage({ id: 'events.trace.counts' }, {
            observed: Math.max(connection.eventCount ?? 0, steps.length), available: steps.length,
          })}</Typography.Text>
          {(connection.eventCount ?? 0) > steps.length && <Typography.Text type="secondary">{t('trace.retention')}</Typography.Text>}
          {connection.connectionCloseObserved === false && !steps.some((step) => step.eventType === 'SessionClosed') &&
            <Typography.Text type="warning">{t('trace.closeUnknown')}</Typography.Text>}
        </Space>}
        <Table rowKey="eventId" size="small" loading={stepsLoading} dataSource={steps} pagination={false} scroll={{ x: 850 }} columns={[
          { title: t('time'), dataIndex: 'occurredAtUtc', render: timeLabel, width: 180 },
          { title: t('event'), dataIndex: 'eventType', render: eventLabel, width: 200 },
          { title: t('result'), dataIndex: 'outcome', render: resultCell, width: 100 },
          { title: t('summary'), key: 'summary', render: (_, record) => stepSummary(record) },
        ]} />
      </Modal>
      <CredentialEvidenceModal target={evidenceTarget} onClose={() => setEvidenceTarget(null)} />
    </div>
  );
};

const EventsPage: React.FC = () => {
  const { search } = useLocation();
  const params = new URLSearchParams(search);
  const eventType = params.get('eventType');

  // 进入新的查询地址时重置筛选和详情，避免请求或导出沿用上一条链接的条件。
  return <EventActivityList
    key={search}
    initialSourceIp={params.get('sourceIp') ?? ''}
    initialEventType={eventType && eventTypes.includes(eventType) ? eventType : undefined}
  />;
};

export default EventsPage;
