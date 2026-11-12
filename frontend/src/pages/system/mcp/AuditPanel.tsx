import { ReloadOutlined } from '@ant-design/icons';
import type { TableColumnsType } from 'antd';
import { Alert, Button, Card, Descriptions, Drawer, Empty, Flex, Form, Input, InputNumber, Popconfirm, Select, Space, Spin, Table, Tabs, Tag, Typography } from 'antd';
import { useEffect, useState } from 'react';
import { getMcpAudit, getMcpAudits, type McpAuditDetails, type McpAuditQuery, type McpAuditSummary, type McpCallResult, type McpPermissions } from '@/services/honeypot/mcp';
import { reportApiError } from '@/utils/reportFormat';
import { beijingTimeToUtc, callResults, formatMcpTime, McpCopyBlock } from './display';

interface AuditFilters {
  keyId?: string;
  tool?: string;
  sourceIp?: string;
  result?: McpCallResult;
  from?: string;
  to?: string;
}

interface AuditPanelProps {
  permissions?: McpPermissions;
  retentionDays?: number;
  settingsSaving: boolean;
  onSaveRetention: (days: number) => Promise<boolean>;
  refreshSettings: () => void;
}

const resultOptions = Object.entries(callResults).map(([value, { label }]) => ({ value, label }));

const AuditResult = ({ result }: { result: McpCallResult }) => <Tag color={callResults[result]?.color}>{callResults[result]?.label ?? result}</Tag>;

export default function AuditPanel({ permissions, retentionDays, settingsSaving, onSaveRetention, refreshSettings }: AuditPanelProps) {
  const [form] = Form.useForm<AuditFilters>();
  const [query, setQuery] = useState<McpAuditQuery>({ page: 1, pageSize: 20 });
  const [rows, setRows] = useState<McpAuditSummary[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [filterError, setFilterError] = useState('');
  const [refresh, setRefresh] = useState(0);
  const [selected, setSelected] = useState<string>();
  const [draftDays, setDraftDays] = useState<number | null>(retentionDays ?? null);

  useEffect(() => setDraftDays(retentionDays ?? null), [retentionDays]);

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setError('');
    void getMcpAudits(query, controller.signal).then((response) => {
      if (controller.signal.aborted) return;
      if (!response.success || !response.data) throw response;
      setRows(response.data.items);
      setTotal(response.data.total);
    }).catch((failure) => {
      if (controller.signal.aborted) return;
      setRows([]);
      setTotal(0);
      setError(reportApiError(failure, '无法读取调用记录，请稍后重试。'));
    }).finally(() => {
      if (!controller.signal.aborted) setLoading(false);
    });
    return () => controller.abort();
  }, [query, refresh]);

  const applyFilters = ({ from, to, tool, keyId, sourceIp, result }: AuditFilters) => {
    const fromUtc = beijingTimeToUtc(from);
    const toUtc = beijingTimeToUtc(to);
    if ((from && !fromUtc) || (to && !toUtc) || (fromUtc && toUtc && fromUtc >= toUtc)) {
      setFilterError('结束时间需晚于开始时间。');
      return;
    }
    setFilterError('');
    setQuery((current) => ({ page: 1, pageSize: current.pageSize, fromUtc, toUtc, tool, keyId: keyId?.trim() || undefined, sourceIp: sourceIp?.trim() || undefined, result }));
  };

  const resetFilters = () => {
    form.resetFields();
    setFilterError('');
    setQuery((current) => ({ page: 1, pageSize: current.pageSize }));
  };

  const saveRetention = async () => {
    if (draftDays === null) return;
    if (await onSaveRetention(draftDays)) {
      setSelected(undefined);
      setQuery((current) => ({ ...current, page: 1 }));
    }
  };

  const canSaveRetention = draftDays !== null && Number.isInteger(draftDays) && draftDays >= 1 && draftDays <= 365 && retentionDays !== undefined && draftDays !== retentionDays;
  const retentionLowered = canSaveRetention && draftDays < retentionDays;
  const saveButton = <Button size="small" loading={settingsSaving} disabled={!canSaveRetention} onClick={retentionLowered ? undefined : saveRetention}>保存留存</Button>;
  const retentionCutoff = retentionLowered ? formatMcpTime(new Date(Date.now() - draftDays * 86_400_000).toISOString()) : '';
  const tools = permissions?.groups.flatMap((group) => group.tools.map((tool) => ({ value: tool.id, label: `${tool.label} · ${tool.id}` })));

  const columns: TableColumnsType<McpAuditSummary> = [
    { title: '时间（北京时间）', dataIndex: 'occurredAtUtc', width: 166, render: formatMcpTime },
    { title: '调用对象', width: 220, ellipsis: true, render: (_, row) => (
      <Button type="link" size="small" onClick={() => setSelected(row.id)} style={{ maxWidth: '100%', paddingInline: 0 }}>
        <Typography.Text ellipsis title={row.tool || row.mcpMethod || row.httpMethod || '请求详情'}>{row.tool || row.mcpMethod || row.httpMethod || '请求详情'}</Typography.Text>
      </Button>
    ) },
    { title: 'API Key', width: 146, ellipsis: true, render: (_, row) => row.keyName || row.keyPrefix || '未知' },
    { title: '来源 IP', dataIndex: 'sourceIp', width: 145, ellipsis: true, render: (ip?: string) => ip || '—' },
    { title: 'HTTP', dataIndex: 'httpStatus', width: 68, render: (status?: number) => status ?? '—' },
    { title: '耗时', dataIndex: 'durationMs', width: 90, render: (duration?: number) => duration == null ? '—' : `${duration} ms` },
    { title: '结果', dataIndex: 'result', width: 105, fixed: 'right', render: (result: McpCallResult) => <AuditResult result={result} /> },
  ];

  return (
    <Card>
      <Flex vertical gap={14}>
        <Flex align="center" justify="space-between" gap={12} wrap="wrap">
          <Typography.Text strong>调用记录</Typography.Text>
          <Space wrap>
            <Typography.Text type="secondary">审计留存</Typography.Text>
            <InputNumber aria-label="审计留存天数" size="small" min={1} max={365} precision={0} value={draftDays} onChange={setDraftDays} disabled={retentionDays === undefined || settingsSaving} style={{ width: 76 }} />
            <Typography.Text type="secondary">天</Typography.Text>
            {retentionLowered ? (
              <Popconfirm title="缩短审计留存？" description={`将清理北京时间 ${retentionCutoff} 之前的记录。`} onConfirm={saveRetention} okText="确认保存" cancelText="取消" okButtonProps={{ danger: true }}>{saveButton}</Popconfirm>
            ) : saveButton}
          </Space>
        </Flex>
        <Form form={form} size="small" layout="inline" onFinish={applyFilters} style={{ gap: 10 }}>
          <Form.Item name="keyId" label="Key ID"><Input className="mcp-filter-input" allowClear maxLength={128} placeholder="含已删除 Key" /></Form.Item>
          <Form.Item name="tool" label="工具">
            {tools ? <Select allowClear showSearch={{ optionFilterProp: 'label' }} placeholder="全部工具" options={tools} style={{ width: 165 }} popupMatchSelectWidth={false} /> : <Input className="mcp-filter-input" allowClear placeholder="工具名" />}
          </Form.Item>
          <Form.Item name="sourceIp" label="来源 IP"><Input className="mcp-filter-input" allowClear maxLength={64} placeholder="IPv4 或 IPv6" /></Form.Item>
          <Form.Item name="result" label="结果"><Select allowClear placeholder="全部" options={resultOptions} style={{ width: 100 }} /></Form.Item>
          <Form.Item name="from" label="开始时间"><Input aria-label="开始时间（北京时间）" type="datetime-local" /></Form.Item>
          <Form.Item name="to" label="结束时间"><Input aria-label="结束时间（北京时间）" type="datetime-local" /></Form.Item>
          <Form.Item>
            <Space>
              <Button type="primary" htmlType="submit">查询</Button>
              <Button onClick={resetFilters}>重置</Button>
              <Button icon={<ReloadOutlined />} aria-label="刷新调用记录" onClick={() => { setRefresh((value) => value + 1); refreshSettings(); }} />
            </Space>
          </Form.Item>
        </Form>
        {filterError && <Alert type="error" showIcon title={filterError} />}
        {error && <Alert type="error" showIcon title={error} />}
        <Table<McpAuditSummary>
          size="small"
          rowKey="id"
          loading={loading}
          columns={columns}
          dataSource={rows}
          scroll={{ x: 940 }}
          locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={error ? '调用记录不可用' : '当前筛选条件下暂无调用记录'} /> }}
          pagination={{ current: query.page, pageSize: query.pageSize, total, showSizeChanger: true, showTotal: (count) => `共 ${count} 条`, onChange: (page, pageSize) => setQuery((current) => ({ ...current, page, pageSize })) }}
        />
      </Flex>
      {selected && <AuditDetails id={selected} onClose={() => setSelected(undefined)} />}
    </Card>
  );
}

function AuditDetails({ id, onClose }: { id: string; onClose: () => void }) {
  const [detail, setDetail] = useState<McpAuditDetails>();
  const [failed, setFailed] = useState(false);
  const [loading, setLoading] = useState(true);
  const [refresh, setRefresh] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    setDetail(undefined);
    setFailed(false);
    setLoading(true);
    void getMcpAudit(id, controller.signal).then((response) => {
      if (controller.signal.aborted) return;
      if (!response.success || !response.data) throw response;
      setDetail(response.data);
    }).catch(() => {
      if (!controller.signal.aborted) setFailed(true);
    }).finally(() => {
      if (!controller.signal.aborted) setLoading(false);
    });
    return () => controller.abort();
  }, [id, refresh]);

  const fields = detail && [
    { key: 'id', label: '记录 ID', children: detail.id },
    { key: 'time', label: '时间（北京时间）', children: formatMcpTime(detail.occurredAtUtc) },
    { key: 'result', label: '结果', children: <AuditResult result={detail.result} /> },
    { key: 'duration', label: '耗时', children: detail.durationMs == null ? '—' : `${detail.durationMs} ms` },
    { key: 'ip', label: '来源 IP', children: detail.sourceIp || '—' },
    { key: 'client', label: '客户端', children: detail.client || '—' },
    { key: 'key', label: 'API Key', children: [detail.keyName, detail.keyPrefix].filter(Boolean).join(' · ') || '未知' },
    { key: 'key-id', label: 'Key ID', children: detail.keyId || '—' },
    { key: 'path', label: 'HTTP 请求', children: [detail.httpMethod, detail.path].filter(Boolean).join(' ') || '—' },
    { key: 'status', label: 'HTTP 状态', children: detail.httpStatus ?? '—' },
    { key: 'method', label: '协议方法', children: detail.mcpMethod || '—' },
    { key: 'version', label: '协议版本', children: detail.protocolVersion || '—' },
    { key: 'tool', label: '工具', children: detail.tool || '—' },
    { key: 'error-code', label: '错误码', children: detail.errorCode || '—' },
    { key: 'request', label: '请求 ID', children: detail.requestId || '—' },
    { key: 'trace', label: '关联 ID', children: detail.traceId || '—' },
    { key: 'request-size', label: '请求大小', children: detail.requestBytes == null ? '—' : `${detail.requestBytes} B` },
    { key: 'response-size', label: '响应大小', children: detail.responseBytes == null ? '—' : `${detail.responseBytes} B` },
  ];

  return (
    <Drawer title="调用详情" open size={840} styles={{ wrapper: { maxWidth: '100vw' } }} onClose={onClose} extra={<Button icon={<ReloadOutlined />} aria-label="刷新调用详情" onClick={() => setRefresh((value) => value + 1)} />}>
      {loading && <Spin />}
      {failed && <Alert type="error" showIcon title="调用详情暂不可用，记录可能已到期或不存在。" />}
      {detail && (
        <Flex vertical gap={12}>
          {detail.captureNote && <Alert type="info" showIcon title={detail.captureNote} />}
          <Tabs items={[
            { key: 'overview', label: '概览', children: (
              <Flex vertical gap={12}>
                <Descriptions size="small" bordered column={{ xs: 1, sm: 2 }} styles={{ content: { overflowWrap: 'anywhere', minWidth: 0 } }} items={fields} />
                {detail.errorMessage && <Alert type="warning" showIcon title="错误详情" description={detail.errorMessage} />}
              </Flex>
            ) },
            { key: 'headers', label: '请求头', children: <McpCopyBlock formatAudit label="请求头" value={detail.requestHeaders} /> },
            { key: 'params', label: '请求参数', children: <McpCopyBlock formatAudit label="请求参数" value={detail.requestParams} emptyText={detail.requestBodyOmittedReason} /> },
            { key: 'response', label: '响应', children: (
              <Flex vertical gap={16}>
                <McpCopyBlock formatAudit label="响应头" value={detail.responseHeaders} />
                <McpCopyBlock formatAudit label="响应体" value={detail.responseBody} emptyText={detail.responseBodyOmittedReason} />
              </Flex>
            ) },
          ]} />
        </Flex>
      )}
    </Drawer>
  );
}
