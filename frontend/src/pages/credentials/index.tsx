import { useAccess, useIntl } from '@umijs/max';
import { Alert, Button, Card, Empty, Spin, Table, Typography } from 'antd';
import type { ColumnsType } from 'antd/es/table';
import React, { useCallback, useEffect, useState } from 'react';
import CredentialEvidenceModal, { type CredentialEvidenceTarget } from '@/components/CredentialEvidenceModal';
import ExcelExportButton from '@/components/ExcelExportButton';
import SourceIp from '@/components/SourceIp';
import { evidenceExportBatchSize, exportCredentialEvidence, getCredentialEvidenceSummaries, normalizePage, type CredentialEvidenceSummary } from '@/services/honeypot/api';
import { connectHoneypotRealtime } from '@/services/realtime';
import { getCapturedPassword, isPasswordMaterial, parseCredentialEvidenceFields } from '@/utils/credentialEvidence';
import { type ExcelCell, MAX_EXCEL_CELL_LENGTH } from '@/utils/exportExcel';
import PasswordCell from './PasswordCell';

const evidenceFields = [
  ['username', 'events.account'], ['domain', 'events.domain'], ['database', 'events.database'],
  ['method', 'events.method'], ['password', 'events.evidence.password'], ['newPassword', 'excel.newPassword'],
] as const;

function appendEvidenceParts(rows: ExcelCell[][], prefix: ExcelCell[], value: string) {
  // Excel 单格最多 32767 字符。分段保留全文，不拆开 UTF-16 代理对。
  let offset = 0;
  let part = 1;
  do {
    let end = Math.min(value.length, offset + 30000);
    const next = value.charCodeAt(end);
    if (next >= 0xdc00 && next <= 0xdfff) end--;
    rows.push([...prefix, part++, value.slice(offset, end)]);
    offset = end;
  } while (offset < value.length);
}

const CredentialsPage: React.FC = () => {
  const access = useAccess();
  const intl = useIntl();
  const t = (id: string) => intl.formatMessage({ id });
  const timeLabel = (value: string) => new Date(value).toLocaleString(intl.locale, { timeZone: 'Asia/Shanghai' });
  const materialLabel = (value: string) => intl.formatMessage({ id: `events.material.${value}`, defaultMessage: t('events.material.unknown') });
  const [evidenceTarget, setEvidenceTarget] = useState<CredentialEvidenceTarget | null>(null);
  const [rows, setRows] = useState<CredentialEvidenceSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);

  const load = useCallback(async () => {
    try {
      const response = await getCredentialEvidenceSummaries();
      setRows(normalizePage(response.data).items);
      setError(false);
    } catch {
      setRows([]);
      setError(true);
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

  const columns: ColumnsType<CredentialEvidenceSummary> = [
    { title: t('credentials.capturedAt'), dataIndex: 'capturedAtUtc', render: timeLabel },
    { title: t('events.sourceIp'), dataIndex: 'sourceIp', width: 180, render: (value: string) => <SourceIp ip={value} /> },
    { title: t('credentials.protocol'), dataIndex: 'adapterKey' },
    { title: t('credentials.materialType'), dataIndex: 'materialType', render: materialLabel },
    {
      title: t('credentials.password'),
      key: 'password',
      width: 180,
      render: (_, record) => access.canAdmin && isPasswordMaterial(record.materialType)
        ? <PasswordCell key={record.credentialArtifactId} artifactId={record.credentialArtifactId} />
        : null,
    },
    { title: t('credentials.eventId'), dataIndex: 'eventId', ellipsis: true },
    { title: t('events.evidence.id'), dataIndex: 'credentialArtifactId', ellipsis: true },
    { title: t('credentials.retentionUntil'), dataIndex: 'retentionUntilUtc', render: (value) => value ? timeLabel(value) : '-' },
    { title: intl.formatMessage({ id: 'events.details' }), render: (_, record) => access.canAdmin ? <Button type="link" onClick={() => setEvidenceTarget({ artifactId: record.credentialArtifactId, adapterKey: record.adapterKey })}>{intl.formatMessage({ id: 'events.evidence.view' })}</Button> : intl.formatMessage({ id: 'events.evidence.adminOnly' }) },
  ];

  return (
    <div>
      <Typography.Title level={3}>{t('credentials.title')}</Typography.Title>
      {error && <Alert title={t('events.evidence.failed')} type="warning" showIcon style={{ marginBottom: 16 }} />}
      <Card extra={access.canAdmin && <ExcelExportButton
        filename="credential-evidence" sheetName={t('credentials.title')} label={t('excel.detailedEvidence')} disabled={loading || error || rows.length === 0}
        headers={['credentials.capturedAt', 'events.sourceIp', 'credentials.protocol', 'credentials.materialType', 'credentials.password', 'credentials.eventId', 'excel.connectionId', 'events.evidence.id', 'credentials.retentionUntil', 'excel.truncated'].map(t)}
        prepare={async () => {
          const ids = rows.map((row) => row.credentialArtifactId);
          const details: ExcelCell[][] = [];
          // 主表和明细表共用同一次经服务端鉴权与审计的原文读取。
          const passwords = new Map<string, string>();
          for (let offset = 0; offset < ids.length; offset += evidenceExportBatchSize) {
            const response = await exportCredentialEvidence(ids.slice(offset, offset + evidenceExportBatchSize));
            if (!response.success || !response.data) throw new Error('Evidence export unavailable');
            for (const item of response.data.items) {
              if (item.outcome !== 'OK' || !item.evidence) {
                details.push([item.artifactId, t('excel.unavailable')]);
                continue;
              }
              const { content, summary } = item.evidence;
              const fields = parseCredentialEvidenceFields(content);
              const password = getCapturedPassword(fields, summary.materialType);
              let passwordCell = password ?? t('credentials.passwordNotCaptured');
              if (password === '') passwordCell = t('events.evidence.emptyPassword');
              else if (password && password.length > MAX_EXCEL_CELL_LENGTH) passwordCell = t('credentials.passwordSeeDetails');
              passwords.set(item.artifactId, passwordCell);
              const prefix = [item.artifactId, t('events.outcome.completed')];
              for (const [field, label] of evidenceFields) {
                const value = fields[field];
                if (typeof value === 'string') appendEvidenceParts(details, [...prefix, t(label)], value);
              }
              appendEvidenceParts(details, [...prefix, t('events.evidence.raw')], content);
            }
          }
          return {
            rows: rows.map((row) => [
              timeLabel(row.capturedAtUtc), row.sourceIp, row.adapterKey, materialLabel(row.materialType),
              passwords.get(row.credentialArtifactId) ?? t('excel.unavailable'),
              row.eventId, row.connectionId, row.credentialArtifactId, row.retentionUntilUtc ? timeLabel(row.retentionUntilUtc) : undefined, row.truncated,
            ]),
            additionalSheets: [{ name: t('events.evidence.raw'), headers: ['events.evidence.id', 'events.result', 'excel.field', 'excel.part', 'excel.value'].map(t), rows: details }],
          };
        }}
      />}>
        {loading ? <Spin /> : rows.length === 0 ? <Empty description="暂无记录" /> : <Table rowKey="credentialArtifactId" dataSource={rows} columns={columns} pagination={{ pageSize: 20 }} />}
      </Card>
      <CredentialEvidenceModal target={evidenceTarget} onClose={() => setEvidenceTarget(null)} />
    </div>
  );
};

export default CredentialsPage;
