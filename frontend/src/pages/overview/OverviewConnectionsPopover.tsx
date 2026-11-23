import { useAccess } from '@umijs/max';
import { Popover, Table, Typography } from 'antd';
import type { ColumnsType } from 'antd/es/table';
import { createStyles } from 'antd-style';
import type { ReactNode } from 'react';
import { useEffect, useId, useRef, useState } from 'react';
import { SourceIpLocation } from '@/components/SourceIp';
import {
  getOverviewConnections,
  type OverviewConnectionFilter,
  type OverviewConnectionRow,
  type OverviewConnectionScope,
} from '@/services/honeypot/api';
import { isPasswordMaterial } from '@/utils/credentialEvidence';
import PasswordCell from '../credentials/PasswordCell';

const pageSize = 5;
const timeFormat = new Intl.DateTimeFormat('zh-CN', {
  timeZone: 'Asia/Shanghai',
  month: '2-digit',
  day: '2-digit',
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
  hourCycle: 'h23',
});

const connectionColumns: ColumnsType<OverviewConnectionRow> = [
  {
    title: '时间',
    dataIndex: 'occurredAtUtc',
    width: 112,
    ellipsis: true,
    render: (value: string) => {
      const timestamp = Date.parse(value);
      if (!Number.isFinite(timestamp)) return '—';
      const time = timeFormat.format(timestamp);
      return (
        <time dateTime={value} title={time}>
          {time}
        </time>
      );
    },
  },
  {
    title: '来源 IP',
    dataIndex: 'sourceIp',
    width: 144,
    ellipsis: true,
    render: (value: string) => value || '—',
  },
  {
    title: '归属地',
    key: 'location',
    width: 164,
    render: (_, row) => <SourceIpLocation ip={row.sourceIp} />,
  },
  {
    title: '服务 / 端口',
    key: 'service',
    width: 100,
    ellipsis: true,
    render: (_, row) => {
      const service = `${row.adapterKey?.toUpperCase() || '—'} / ${row.destinationPort}`;
      return <span title={service}>{service}</span>;
    },
  },
];

const sourceActivityNames: Record<string, string> = {
  connectionaccepted: '已接纳连接',
  connectionrejected: '准入拒绝',
  authenticationattempted: '认证失败',
  protocolviolation: '协议异常',
};

const sourceActivityColumn: ColumnsType<OverviewConnectionRow>[number] = {
  title: '最近活动',
  dataIndex: 'eventType',
  width: 100,
  render: (eventType?: string | null) =>
    sourceActivityNames[eventType?.toLowerCase() ?? ''] ?? '—',
};

const violationSummaryColumn: ColumnsType<OverviewConnectionRow>[number] = {
  title: '异常说明',
  dataIndex: 'protocolViolationSummary',
  width: 220,
  render: (summary?: string | null) => (
    <bdi style={{ overflowWrap: 'anywhere' }}>{summary || '—'}</bdi>
  ),
};

function authenticationColumns(
  canAdmin: boolean,
): ColumnsType<OverviewConnectionRow> {
  return [
    {
      title: '账号',
      dataIndex: 'username',
      width: 104,
      render: (username?: string | null) => (
        <bdi style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>
          {username || '—'}
        </bdi>
      ),
    },
    {
      title: '密码',
      key: 'password',
      render: (_, row) => {
        if (
          !row.credentialArtifactId ||
          !row.materialType ||
          !isPasswordMaterial(row.materialType)
        )
          return <Typography.Text type="secondary">未采集密码</Typography.Text>;
        if (!canAdmin)
          return (
            <Typography.Text type="secondary">仅管理员可查看</Typography.Text>
          );

        return (
          <PasswordCell
            key={row.credentialArtifactId}
            artifactId={row.credentialArtifactId}
            emptyPasswordText="（空密码）"
            loadingText="正在读取…"
            unavailableText="密码不可用"
          />
        );
      },
    },
  ];
}

const useStyles = createStyles(({ css, token }) => ({
  anchor: css`
    position: relative;
    min-width: 0;
  `,
  button: css`
    display: block;
    width: 100%;
    padding: 0;
    background: transparent;
    border: 0;
    border-radius: ${token.borderRadius}px;
    color: inherit;
    font: inherit;
    text-align: start;
    cursor: pointer;
    &:hover > span:first-child { color: ${token.colorPrimaryText}; }
    &:focus-visible { outline: 2px solid ${token.colorPrimary}; outline-offset: 4px; }
  `,
  content: css`
    width: min(520px, calc(100vw - 48px));
  `,
  authenticationContent: css`
    width: min(780px, calc(100vw - 48px));
  `,
  // 预留表头和五行高度，让末页的分页按钮仍在同一位置。
  pagedTable: css`
    min-height: ${(pageSize + 1) * (Math.round(token.fontSize * token.lineHeight) + token.paddingXS * 2 + token.lineWidth)}px;
  `,
}));

interface ConnectionPage {
  page: number;
  rows: OverviewConnectionRow[];
  total: number;
  error?: string;
}

export function OverviewConnectionsDetails({
  filter,
}: { filter: OverviewConnectionFilter }) {
  const { styles } = useStyles();
  const { canAdmin } = useAccess();
  const metric = filter.scope === 'adapterActivity' ? filter.metric : undefined;
  const authentication =
    filter.scope === 'authenticationFailures' ||
    metric === 'authenticationFailures';
  const [page, setPage] = useState(1);
  const [result, setResult] = useState<ConnectionPage>();

  useEffect(() => {
    let current = true;
    // 气泡关闭或切换页码后，忽略旧请求返回的数据。
    async function load() {
      try {
        const response = await getOverviewConnections({
          ...filter,
          page,
          pageSize,
        });
        if (!response.success || !response.data)
          throw new Error(response.code);
        if (!current) return;
        const { items, total } = response.data;
        const lastPage = Math.max(1, Math.ceil(total / pageSize));
        if (page > lastPage) {
          // 活动连接关闭后页数可能减少，回到当前有效的最后一页。
          setResult({ page, rows: [], total });
          setPage(lastPage);
          return;
        }
        setResult({ page, rows: items, total });
      } catch (error) {
        const expired = (error as { response?: { status?: number } } | null)?.response?.status === 410
          || (error instanceof Error && error.message === 'OVERVIEW_SNAPSHOT_EXPIRED');
        if (current)
          setResult((previous) => ({
            page,
            rows: [],
            total: expired ? 0 : previous?.total ?? 0,
            error: expired ? '活动连接快照已过期，请刷新首页后重新打开明细。' : '连接明细暂不可用',
          }));
      }
    }
    void load();
    return () => {
      current = false;
    };
  }, [filter, page]);

  const loading = result?.page !== page;
  const extraColumns = authentication
    ? authenticationColumns(canAdmin)
    : metric === 'sourceIpCount'
      ? [sourceActivityColumn]
      : metric === 'protocolViolations'
        ? [violationSummaryColumn]
        : [];
  const columns = [...connectionColumns, ...extraColumns];
  const width = authentication
    ? 780
    : 520 + extraColumns.reduce((sum, column) => sum + Number(column.width), 0);
  return (
    <Table<OverviewConnectionRow>
      classNames={{
        section:
          (result?.total ?? 0) > pageSize ? styles.pagedTable : undefined,
      }}
      columns={columns}
      // 切页先卸载旧密码单元格，停止其读取并清除原文。
      dataSource={authentication && loading ? [] : (result?.rows ?? [])}
      loading={loading}
      rowKey="id"
      size="small"
      tableLayout="fixed"
      scroll={{ x: width, y: 'min(320px, 45vh)' }}
      pagination={{
        current: page,
        pageSize,
        total: result?.total,
        size: 'small',
        showSizeChanger: false,
        hideOnSinglePage: true,
        onChange: setPage,
        styles: { root: { marginBottom: 0 } },
      }}
      locale={{
        emptyText: result?.error ?? '暂无连接记录',
      }}
    />
  );
}

interface OverviewConnectionsPopoverProps {
  scope: OverviewConnectionScope;
  label: string;
  asOfUtc?: string;
  children: ReactNode;
}

export default function OverviewConnectionsPopover({
  scope,
  label,
  asOfUtc,
  children,
}: OverviewConnectionsPopoverProps) {
  const { styles } = useStyles();
  const [filter, setFilter] = useState<OverviewConnectionFilter>();
  const open = Boolean(filter);
  // 打开时固定该卡片的统计时点，后续自动刷新不能改变翻页的时间窗。
  const setOpen = (visible: boolean) => setFilter((current) =>
    visible ? current ?? (asOfUtc ? { scope, asOfUtc } : { scope }) : undefined);
  const button = useRef<HTMLButtonElement>(null);
  const popupId = useId();
  const popupTitle = scope === 'threatConnections' ? '威胁 IP 最近连接' : label;

  return (
    <div
      className={styles.anchor}
      onBlur={(event) => {
        if (
          event.relatedTarget &&
          !event.currentTarget.contains(event.relatedTarget)
        )
          setOpen(false);
      }}
      onKeyDown={(event) => {
        if (event.key === 'Escape' && open) {
          setOpen(false);
          button.current?.focus();
        }
      }}
    >
      <Popover
        title={popupTitle}
        open={open}
        onOpenChange={setOpen}
        trigger={['hover', 'click']}
        placement="bottom"
        mouseLeaveDelay={0.2}
        destroyOnHidden
        fresh
        // 气泡紧跟指标按钮，键盘可以按 Tab 进入分页控件。
        getPopupContainer={(trigger) => trigger.parentElement ?? trigger}
        content={
          filter ? (
            <div
              id={popupId}
              className={
                scope === 'authenticationFailures'
                  ? styles.authenticationContent
                  : styles.content
              }
              role="dialog"
              aria-label={popupTitle}
            >
              {scope === 'threatConnections' && (
                <Typography.Text type="secondary">
                  每个来源显示最近一条留存连接
                </Typography.Text>
              )}
              <OverviewConnectionsDetails filter={filter} />
            </div>
          ) : null
        }
      >
        <button
          type="button"
          ref={button}
          className={styles.button}
          aria-haspopup="dialog"
          aria-expanded={open}
          aria-controls={open ? popupId : undefined}
        >
          {children}
        </button>
      </Popover>
    </div>
  );
}
