import { ReloadOutlined } from '@ant-design/icons';
import { useAccess, useLocation } from '@umijs/max';
import { Alert, Button, Card, Descriptions, Drawer, Empty, Form, Input, Select, Space, Spin, Table, Tabs, Tag, Typography } from 'antd';
import { useEffect, useState } from 'react';
import EmailPreview from '@/components/EmailPreview';
import { getEmailDeliveries, getEmailDelivery, type EmailDeliveryDetails, type EmailDeliveryQuery, type EmailDeliverySummary, mailKindLabels, mailStatusLabels, retryEmailDelivery } from '@/services/honeypot/notifications';
import { formatReportTime, reportApiError, reportDateRange } from '@/utils/reportFormat';

const statusColors: Record<string, string> = { Accepted: 'success', Failed: 'error', Pending: 'processing', Sending: 'processing', Retrying: 'warning', Unknown: 'warning' };
const Status = ({ status }: { status: string }) => <Tag color={statusColors[status]}>{mailStatusLabels[status] ?? status}</Tag>;

export default function MailRecordsPage() {
  const access = useAccess();
  return access.canAdmin ? <MailRecordsContent /> : <Alert type="error" title="仅管理员可访问邮件记录。" />;
}

function MailRecordsContent() {
  const { search } = useLocation();
  const initialParams = new URLSearchParams(search);
  const [query, setQuery] = useState<EmailDeliveryQuery>({ page: 1, pageSize: 20, status: initialParams.get('status') === 'all' ? undefined : 'Accepted' });
  const [rows, setRows] = useState<EmailDeliverySummary[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [refresh, setRefresh] = useState(0);
  const [selectedId, setSelectedId] = useState<string | undefined>(initialParams.get('id') ?? undefined);
  const [details, setDetails] = useState<EmailDeliveryDetails>();
  const [detailsLoading, setDetailsLoading] = useState(false);
  const [detailsError, setDetailsError] = useState('');
  const [retrying, setRetrying] = useState(false);
  const [feedback, setFeedback] = useState<{ type: 'success' | 'error'; text: string }>();
  const [filterForm] = Form.useForm<{ kind?: string; recipient?: string; from?: string; to?: string }>();

  useEffect(() => {
    const controller = new AbortController(); let active = true;
    setLoading(true); setError('');
    void getEmailDeliveries(query, controller.signal).then((response) => {
      if (!active) return;
      if (!response.success || !response.data) throw new Error('Unavailable');
      setRows(response.data.items); setTotal(response.data.total);
    }).catch(() => { if (active) { setError('邮件记录暂不可用，请检查管理员权限或稍后重试。'); setRows([]); setTotal(0); } })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; controller.abort(); };
  }, [query, refresh]);

  useEffect(() => {
    const controller = new AbortController(); let active = true;
    setDetails(undefined); setDetailsError(''); setDetailsLoading(Boolean(selectedId));
    if (selectedId) void getEmailDelivery(selectedId, controller.signal).then((response) => {
      if (!active) return;
      if (!response.success || !response.data) throw new Error('Unavailable');
      setDetails(response.data);
    }).catch(() => { if (active) setDetailsError('邮件详情暂不可用，记录可能不存在或无权访问。'); })
      .finally(() => { if (active) setDetailsLoading(false); });
    return () => { active = false; controller.abort(); };
  }, [selectedId, refresh]);

  const retry = async () => {
    if (!selectedId || !details?.canRetry) return;
    setRetrying(true); setFeedback(undefined);
    try {
      const response = await retryEmailDelivery(selectedId);
      if (!response.success) throw response;
      setFeedback({ type: 'success', text: `邮件已重新加入发送队列，任务：${response.data.deliveryIds.join('、')}` });
      setRefresh((value) => value + 1);
    } catch (error) { setFeedback({ type: 'error', text: reportApiError(error, '重新发送未成功，请检查邮件配置、任务状态和冷却时间。') }); }
    finally { setRetrying(false); }
  };

  return <Space orientation="vertical" size={20} style={{ display: 'flex' }}>
    <div><Typography.Title level={3}>邮件记录</Typography.Title><Typography.Paragraph type="secondary">查看日报、周报、月报与测试邮件的发送过程和完整内容。</Typography.Paragraph></div>
    <Alert type="info" showIcon title="“SMTP 已受理”表示邮件服务器接受了发送请求，不代表收件人已收到或已读。" />
    {feedback && <Alert type={feedback.type} title={feedback.text} showIcon />}
    {error && <Alert type="error" title={error} showIcon />}
    <Card>
      <Tabs activeKey={query.status ?? 'all'} onChange={(status) => setQuery((current) => ({ ...current, page: 1, status: status === 'all' ? undefined : status }))} items={[{ key: 'Accepted', label: '已发送' }, { key: 'all', label: '全部' }, { key: 'Pending', label: '排队中' }, { key: 'Sending', label: '发送中' }, { key: 'Retrying', label: '等待重试' }, { key: 'Failed', label: '失败' }, { key: 'Unknown', label: '结果未知' }]} />
      <Form form={filterForm} layout="inline" onFinish={(values) => {
        const range = values.from && values.to ? reportDateRange(values.from, values.to) : undefined;
        if ((values.from || values.to) && !range) { setFeedback({ type: 'error', text: '请同时选择有效的开始与结束日期。' }); return; }
        setFeedback(undefined); setQuery((current) => ({ ...current, page: 1, kind: values.kind, recipient: values.recipient?.trim() || undefined, fromUtc: range?.fromUtc, toUtc: range?.toUtc }));
      }} style={{ gap: 12, marginBottom: 20 }}>
        <Form.Item name="kind" label="类型"><Select allowClear placeholder="全部类型" style={{ width: 130 }} options={Object.entries(mailKindLabels).map(([value, label]) => ({ value, label }))} /></Form.Item>
        <Form.Item name="recipient" label="收件人"><Input placeholder="邮箱地址" allowClear /></Form.Item>
        <Form.Item name="from" label="开始日期"><Input type="date" /></Form.Item><Form.Item name="to" label="结束日期"><Input type="date" /></Form.Item>
        <Form.Item><Space><Button type="primary" htmlType="submit">查询</Button><Button onClick={() => { filterForm.resetFields(); setQuery({ page: 1, pageSize: query.pageSize, status: query.status }); }}>重置</Button><Button icon={<ReloadOutlined />} onClick={() => setRefresh((value) => value + 1)}>刷新</Button></Space></Form.Item>
      </Form>
      <Table rowKey="id" loading={loading} dataSource={rows} scroll={{ x: 1060 }} pagination={{ current: query.page, pageSize: query.pageSize, total, showSizeChanger: true, showTotal: (count) => `共 ${count} 封`, onChange: (page, pageSize) => setQuery((current) => ({ ...current, page, pageSize })) }} columns={[
        { title: '类型', dataIndex: 'kind', width: 110, render: (kind: string) => mailKindLabels[kind] ?? kind },
        { title: '邮件主题', dataIndex: 'subject', width: 260, ellipsis: true, render: (subject: string, row: EmailDeliverySummary) => <Button type="link" onClick={() => setSelectedId(row.id)} style={{ padding: 0, maxWidth: '100%', overflow: 'hidden', textOverflow: 'ellipsis' }}>{subject}</Button> },
        { title: '收件人', dataIndex: 'recipient', width: 220, ellipsis: true },
        { title: '状态', dataIndex: 'status', width: 130, render: (status: string) => <Status status={status} /> },
        { title: '创建时间', dataIndex: 'createdAtUtc', width: 170, render: formatReportTime },
        { title: '受理时间', dataIndex: 'sentAtUtc', width: 170, render: formatReportTime },
        { title: '尝试', dataIndex: 'attemptCount', width: 70 },
      ]} locale={{ emptyText: <Empty description={error ? '邮件记录不可用' : '当前筛选条件下暂无邮件'} /> }} />
    </Card>
    <Drawer title="邮件发送详情" open={Boolean(selectedId)} onClose={() => setSelectedId(undefined)} size={960} styles={{ wrapper: { maxWidth: 'calc(100vw - 24px)' } }} destroyOnHidden extra={<Button icon={<ReloadOutlined />} onClick={() => setRefresh((value) => value + 1)}>刷新</Button>}>
      {detailsLoading && <Spin />}{detailsError && <Alert type="error" title={detailsError} />}
      {details && <Space orientation="vertical" size={20} style={{ display: 'flex' }}>
        <Descriptions column={{ xs: 1, sm: 2 }} bordered size="small" styles={{ label: { whiteSpace: 'nowrap', width: 88 }, content: { overflowWrap: 'anywhere', minWidth: 0 } }} items={[
          { key: 'id', label: '任务 ID', children: details.delivery.id, span: 'filled' },
          { key: 'subject', label: '主题', children: details.delivery.subject, span: 'filled' },
          { key: 'recipient', label: '收件人', children: details.delivery.recipient },
          { key: 'status', label: '状态', children: <Status status={details.delivery.status} /> },
          { key: 'created', label: '创建时间', children: formatReportTime(details.delivery.createdAtUtc) },
          { key: 'sent', label: '受理时间', children: formatReportTime(details.delivery.sentAtUtc) },
          { key: 'next', label: '下次尝试', children: formatReportTime(details.delivery.nextAttemptAtUtc) },
          { key: 'template', label: '模板版本', children: details.templateVersion },
          ...(details.delivery.periodStartAtUtc ? [{ key: 'period', label: '报告区间', children: `${formatReportTime(details.delivery.periodStartAtUtc)} 至 ${formatReportTime(details.delivery.periodEndAtUtc)}`, span: 'filled' as const }] : []),
        ]} />
        {details.delivery.lastErrorCode && <Alert type="warning" showIcon title={details.delivery.lastErrorCode} description={details.delivery.lastErrorMessage ?? '发送失败，请检查配置后重试。'} />}
        {details.delivery.status === 'Unknown' && <Alert type="warning" showIcon title="发送结果未知，邮件可能已被 SMTP 服务器接受。请核实后再重发，以免重复投递。" />}
        {details.canRetry && <Button onClick={retry} loading={retrying}>重新发送</Button>}
        <Tabs items={[{ key: 'html', label: 'HTML 邮件', children: <EmailPreview html={details.htmlBody} /> }, { key: 'text', label: '纯文本', children: <Typography.Paragraph style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{details.textBody}</Typography.Paragraph> }, { key: 'attempts', label: '发送尝试', children: <Table rowKey="attemptNumber" size="small" dataSource={details.attempts} pagination={false} scroll={{ x: 650 }} columns={[{ title: '次数', dataIndex: 'attemptNumber', width: 65 }, { title: '开始', dataIndex: 'startedAtUtc', render: formatReportTime, width: 170 }, { title: '完成', dataIndex: 'completedAtUtc', render: formatReportTime, width: 170 }, { title: '结果', dataIndex: 'outcome', render: (status: string) => mailStatusLabels[status] ?? status }, { title: '错误', render: (_, row) => [row.errorCode, row.errorMessage].filter(Boolean).join(' · ') || '—' }]} /> }]} />
      </Space>}
    </Drawer>
  </Space>;
}
