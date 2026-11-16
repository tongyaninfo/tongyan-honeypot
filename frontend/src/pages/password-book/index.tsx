import { useAccess, useIntl } from '@umijs/max';
import { Alert, Button, Card, Input, Table, Typography } from 'antd';
import type { ColumnsType } from 'antd/es/table';
import { useEffect, useRef, useState } from 'react';
import englishMessages from '@/locales/en-US/events';
import {
  evidenceExportBatchSize,
  exportCredentialEvidence,
  getPasswordBook,
  loadExportRows,
  type PasswordBookRow,
} from '@/services/honeypot/api';
import {
  getCapturedPassword,
  parseCredentialEvidenceFields,
} from '@/utils/credentialEvidence';
import { exportCsv } from '@/utils/exportCsv';
import PasswordCell from '../credentials/PasswordCell';

const pageSize = 20;
const maxKeywordLength = 128;
const defaultMessages: Record<string, string> = englishMessages;

interface PasswordBookSnapshot {
  query: { page: number; keyword: string };
  total: number;
  rows: PasswordBookRow[];
  status: 'loading' | 'loaded' | 'failed';
}

export default function PasswordBookPage() {
  const access = useAccess();
  const intl = useIntl();
  return access.canAdmin ? (
    <PasswordBookContent />
  ) : (
    <Alert
      type="error"
      showIcon
      title={intl.formatMessage({ id: 'passwordBook.adminOnly' })}
    />
  );
}

function PasswordBookContent() {
  const intl = useIntl();
  const t = (id: string, values?: Record<string, string | number>) =>
    intl.formatMessage({ id, defaultMessage: defaultMessages[id] }, values);
  const [draftKeyword, setDraftKeyword] = useState('');
  const [snapshot, setSnapshot] = useState<PasswordBookSnapshot>({
    query: { page: 1, keyword: '' },
    total: 0,
    rows: [],
    status: 'loading',
  });
  const { query, total, rows, status } = snapshot;
  const { page, keyword } = query;
  const exportInFlight = useRef<AbortController | null>(null);
  const [exporting, setExporting] = useState(false);
  const [exportFeedback, setExportFeedback] = useState<{
    type: 'success' | 'warning' | 'error';
    text: string;
  }>();

  useEffect(() => {
    const controller = new AbortController();
    const { page, keyword } = query;
    void getPasswordBook(
      { page, pageSize, ...(keyword ? { keyword } : {}) },
      controller.signal,
    )
      .then(({ success, data }) => {
        if (controller.signal.aborted) return;
        if (!success || !data) throw new Error('Password book unavailable');
        const lastPage = Math.max(1, Math.ceil(data.total / pageSize));
        setSnapshot((current) => {
          if (current.query !== query) return current;
          // 证据到期可能减少页数，存在的最后一页重新查询。
          return page > lastPage
            ? {
                query: { page: lastPage, keyword },
                total: data.total,
                rows: [],
                status: 'loading',
              }
            : { query, total: data.total, rows: data.items, status: 'loaded' };
        });
      })
      .catch(() => {
        if (!controller.signal.aborted) {
          setSnapshot((current) =>
            current.query === query
              ? { ...current, status: 'failed' }
              : current,
          );
        }
      });
    return () => controller.abort();
  }, [query]);

  useEffect(() => () => exportInFlight.current?.abort(), []);

  const changeQuery = (nextPage: number, nextKeyword: string) => {
    // 换页或筛选时先卸载密码单元格，取消旧记录的原文读取。
    setSnapshot((current) =>
      current.query.page === nextPage &&
      current.query.keyword === nextKeyword &&
      current.status !== 'failed'
        ? current
        : {
            query: { page: nextPage, keyword: nextKeyword },
            total: current.query.keyword === nextKeyword ? current.total : 0,
            rows: [],
            status: 'loading',
          },
    );
  };

  const download = async () => {
    if (exportInFlight.current) return;
    const controller = new AbortController();
    const { signal } = controller;
    exportInFlight.current = controller;
    setExporting(true);
    setExportFeedback(undefined);

    try {
      // 重新从第一页读取点击导出时已应用的筛选，导出与当前页码无关。
      const matches = await loadExportRows(
        (query) => {
          signal.throwIfAborted();
          return getPasswordBook(
            { ...query, ...(keyword ? { keyword } : {}) },
            signal,
          );
        },
        (row) => row.credentialArtifactId,
      );
      if (signal.aborted) return;
      if (matches.length === 0) {
        setExportFeedback({
          type: 'warning',
          text: t('passwordBook.exportEmpty'),
        });
        return;
      }

      const csvRows: (string | number)[][] = [];
      let unavailable = 0;
      for (
        let offset = 0;
        offset < matches.length;
        offset += evidenceExportBatchSize
      ) {
        const batch = matches.slice(offset, offset + evidenceExportBatchSize);
        const response = await exportCredentialEvidence(
          batch.map((row) => row.credentialArtifactId),
          signal,
        );
        if (signal.aborted) return;
        if (!response.success || !response.data)
          throw new Error('Evidence export unavailable');
        const items = new Map(
          response.data.items.map((item) => [item.artifactId, item]),
        );

        for (const row of batch) {
          const item = items.get(row.credentialArtifactId);
          const evidence = item?.outcome === 'OK' ? item.evidence : undefined;
          const expiresAt = Date.parse(
            evidence?.summary.retentionUntilUtc ?? '',
          );
          const password =
            evidence?.summary.credentialArtifactId ===
              row.credentialArtifactId &&
            (Number.isNaN(expiresAt) || expiresAt > Date.now())
              ? getCapturedPassword(
                  parseCredentialEvidenceFields(evidence.content),
                  evidence.summary.materialType,
                )
              : undefined;
          if (password === undefined) unavailable++;
          csvRows.push([
            row.username,
            password ?? '',
            row.adapterKey.toUpperCase(),
            row.authenticationCount,
            row.lastUsedAtUtc,
            t(
              password === undefined
                ? 'passwordBook.unavailablePassword'
                : 'passwordBook.evidenceAvailable',
            ),
          ]);
        }
      }
      exportCsv(
        'password-book',
        [
          'passwordBook.account',
          'credentials.password',
          'passwordBook.service',
          'passwordBook.authCount',
          'passwordBook.lastUsedUtc',
          'passwordBook.evidenceStatus',
        ].map((id) => t(id)),
        csvRows,
      );
      setExportFeedback({
        type: unavailable ? 'warning' : 'success',
        text: t(
          unavailable
            ? 'passwordBook.exportPartial'
            : 'passwordBook.exportSuccess',
          { count: csvRows.length, unavailable },
        ),
      });
    } catch {
      if (!signal.aborted)
        setExportFeedback({
          type: 'error',
          text: t('passwordBook.exportFailed'),
        });
    } finally {
      exportInFlight.current = null;
      if (!signal.aborted) setExporting(false);
    }
  };
  const columns: ColumnsType<PasswordBookRow> = [
    {
      title: t('passwordBook.account'),
      dataIndex: 'username',
      width: '20%',
      render: (username: string) => (
        <bdi style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>
          {username || '—'}
        </bdi>
      ),
    },
    {
      title: t('credentials.password'),
      key: 'password',
      width: '32%',
      render: (_, row) => (
        <PasswordCell
          artifactId={row.credentialArtifactId}
          emptyPasswordText={t('passwordBook.emptyPassword')}
          loadingText={t('passwordBook.loadingPassword')}
          unavailableText={t('passwordBook.unavailablePassword')}
        />
      ),
    },
    {
      title: t('passwordBook.service'),
      dataIndex: 'adapterKey',
      render: (key: string) => key.toUpperCase(),
    },
    {
      title: t('passwordBook.authCount'),
      dataIndex: 'authenticationCount',
      align: 'right',
      render: (count: number) => intl.formatNumber(count),
    },
    {
      title: t('passwordBook.lastUsed'),
      dataIndex: 'lastUsedAtUtc',
      render: (value: string) => (
        <time dateTime={value}>
          {new Date(value).toLocaleString(intl.locale, {
            timeZone: 'Asia/Shanghai',
          })}
        </time>
      ),
    },
  ];

  return (
    <div>
      <Typography.Title level={3}>{t('menu.passwordBook')}</Typography.Title>
      <Card>
        <div
          style={{
            display: 'flex',
            flexWrap: 'wrap',
            gap: 8,
            marginBottom: 16,
          }}
        >
          <form
            onSubmit={(event) => {
              event.preventDefault();
              changeQuery(1, draftKeyword.trim());
            }}
            style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}
          >
            <Input
              aria-label={t('passwordBook.searchPlaceholder')}
              placeholder={t('passwordBook.searchPlaceholder')}
              value={draftKeyword}
              onChange={(event) => setDraftKeyword(event.target.value)}
              autoComplete="off"
              maxLength={maxKeywordLength}
              style={{ width: 'min(240px, 100%)' }}
            />
            <Button type="primary" htmlType="submit">
              {t('passwordBook.search')}
            </Button>
            <Button
              disabled={!draftKeyword && !keyword}
              onClick={() => {
                setDraftKeyword('');
                changeQuery(1, '');
              }}
            >
              {t('passwordBook.clear')}
            </Button>
          </form>
          <Button
            onClick={download}
            disabled={status !== 'loaded' || rows.length === 0 || exporting}
            loading={exporting}
          >
            {t('passwordBook.exportCsv')}
          </Button>
        </div>
        {exportFeedback && (
          <Alert
            type={exportFeedback.type}
            title={exportFeedback.text}
            showIcon
            style={{ marginBottom: 16 }}
          />
        )}
        <Table<PasswordBookRow>
          columns={columns}
          dataSource={rows}
          loading={status === 'loading'}
          rowKey="credentialArtifactId"
          scroll={{ x: 720 }}
          tableLayout="fixed"
          locale={{
            emptyText:
              status === 'failed'
                ? t('passwordBook.unavailable')
                : t(keyword ? 'passwordBook.noMatches' : 'passwordBook.empty'),
          }}
          pagination={{
            current: page,
            pageSize,
            total,
            hideOnSinglePage: true,
            showSizeChanger: false,
            onChange: (nextPage) => changeQuery(nextPage, keyword),
          }}
        />
      </Card>
    </div>
  );
}
