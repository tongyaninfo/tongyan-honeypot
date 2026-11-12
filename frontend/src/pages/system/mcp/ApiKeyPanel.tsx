import { PlusOutlined, ReloadOutlined } from '@ant-design/icons';
import type { TableColumnsType } from 'antd';
import { Alert, Button, Card, Descriptions, Empty, Flex, Form, Input, Modal, Popconfirm, Radio, Select, Space, Table, Tag, Tree, Typography } from 'antd';
import { useEffect, useState } from 'react';
import { createMcpKey, deleteMcpKey, getMcpKeys, type McpAccess, type McpKey, type McpKeyCreated, type McpPermissions, revokeMcpKey } from '@/services/honeypot/mcp';
import { reportApiError } from '@/utils/reportFormat';
import { accessLabels, beijingTimeToUtc, connectionInstructions, formatMcpTime, keyStates, McpCopyBlock, writeMcpClipboard } from './display';

interface ApiKeyPanelProps {
  origin: string;
  permissions?: McpPermissions;
  permissionsError: boolean;
  reloadPermissions: () => void;
}

export default function ApiKeyPanel({ origin, permissions, permissionsError, reloadPermissions }: ApiKeyPanelProps) {
  const [query, setQuery] = useState({ page: 1, pageSize: 20 });
  const [keys, setKeys] = useState<McpKey[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [failed, setFailed] = useState(false);
  const [refresh, setRefresh] = useState(0);
  const [createOpen, setCreateOpen] = useState(false);
  const [created, setCreated] = useState<McpKeyCreated>();
  const [inspected, setInspected] = useState<McpKey>();
  const [instructionsOpen, setInstructionsOpen] = useState(false);
  const [pendingId, setPendingId] = useState<string>();
  const [feedback, setFeedback] = useState<{ type: 'success' | 'error'; text: string }>();
  const instructions = connectionInstructions(origin);

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setFailed(false);
    void getMcpKeys(query, controller.signal).then((response) => {
      if (controller.signal.aborted) return;
      if (!response.success || !response.data) throw response;
      setKeys(response.data.items);
      setTotal(response.data.total);
    }).catch(() => {
      if (controller.signal.aborted) return;
      setFailed(true);
      setKeys([]);
      setTotal(0);
    }).finally(() => {
      if (!controller.signal.aborted) setLoading(false);
    });
    return () => controller.abort();
  }, [query, refresh]);

  const reload = () => setRefresh((value) => value + 1);

  const mutateKey = async (key: McpKey, operation: 'revoke' | 'delete') => {
    const deleting = operation === 'delete';
    setPendingId(key.id);
    setFeedback(undefined);
    try {
      const response = await (deleting ? deleteMcpKey(key.id) : revokeMcpKey(key.id));
      if (!response.success) throw response;
      setFeedback({ type: 'success', text: deleting ? 'API Key 已删除。' : 'API Key 已吊销。' });
      if (deleting && keys.length === 1 && query.page > 1) {
        setQuery((value) => ({ ...value, page: value.page - 1 }));
      } else {
        reload();
      }
    } catch (error) {
      setFeedback({ type: 'error', text: reportApiError(error, deleting ? '删除失败，请稍后重试。' : '吊销失败，请稍后重试。') });
    } finally {
      setPendingId(undefined);
    }
  };

  const copyInstructions = async () => {
    if (await writeMcpClipboard(instructions)) {
      setFeedback({ type: 'success', text: '接入指令已复制。' });
    } else {
      setInstructionsOpen(true);
    }
  };

  const columns: TableColumnsType<McpKey> = [
    { title: '名称', dataIndex: 'name', width: 180, ellipsis: true },
    { title: '标识前缀', dataIndex: 'prefix', width: 160, ellipsis: true, render: (prefix: string) => <Typography.Text code>{prefix}</Typography.Text> },
    { title: '授权', dataIndex: 'access', width: 76, render: (access: McpAccess) => <Tag color={access === 'ReadWrite' ? 'blue' : 'default'}>{accessLabels[access]}</Tag> },
    { title: '权限数', width: 78, render: (_, row) => row.permissionIds.length },
    { title: '状态', dataIndex: 'status', width: 92, render: (status: McpKey['status']) => <Tag color={keyStates[status]?.color}>{keyStates[status]?.label ?? status}</Tag> },
    { title: '创建时间', dataIndex: 'createdAtUtc', width: 166, render: formatMcpTime },
    { title: '过期时间', dataIndex: 'expiresAtUtc', width: 166, render: (value: string | null) => value ? formatMcpTime(value) : '永久有效' },
    { title: '最近调用', dataIndex: 'lastUsedAtUtc', width: 166, render: formatMcpTime },
    { title: '操作', width: 245, render: (_, row) => (
      <Space size={4}>
        <Button type="link" size="small" onClick={() => setInspected(row)}>查看权限</Button>
        <Button type="link" size="small" onClick={copyInstructions}>复制接入指令</Button>
        {row.status === 'Revoked' ? (
          <Popconfirm title="删除此 API Key？" description="删除后无法恢复，已有调用记录会保留。" okText="删除" cancelText="取消" okButtonProps={{ danger: true }} onConfirm={() => mutateKey(row, 'delete')}>
            <Button type="link" size="small" danger loading={pendingId === row.id} disabled={Boolean(pendingId)}>删除</Button>
          </Popconfirm>
        ) : (
          <Popconfirm title="吊销此 API Key？" description="吊销后立即拒绝使用该 Key 的新调用。" okText="吊销" cancelText="取消" okButtonProps={{ danger: true }} onConfirm={() => mutateKey(row, 'revoke')}>
            <Button type="link" size="small" danger loading={pendingId === row.id} disabled={Boolean(pendingId)}>吊销</Button>
          </Popconfirm>
        )}
      </Space>
    ) },
  ];

  const permissionNames = new Map(permissions?.groups.flatMap((group) => group.tools.map((tool) => [tool.id, tool.label])));
  const instanceNames = new Map(permissions?.instances.map((instance) => [instance.id, instance.name]));

  return (
    <Card title="API Key" extra={(
      <Space>
        <Button icon={<ReloadOutlined />} aria-label="刷新 API Key" onClick={reload} />
        <Button type="primary" icon={<PlusOutlined aria-hidden />} disabled={!permissions} onClick={() => setCreateOpen(true)}>新建 API Key</Button>
      </Space>
    )}>
      <Flex vertical gap={12}>
        {permissionsError && <Alert type="error" showIcon title="无法读取权限目录" action={<Button size="small" onClick={reloadPermissions}>重试</Button>} />}
        {feedback && <Alert type={feedback.type} showIcon title={feedback.text} />}
        {failed && <Alert type="error" showIcon title="无法读取 API Key 列表" />}
        <Table<McpKey>
          size="small"
          rowKey="id"
          loading={loading}
          columns={columns}
          dataSource={keys}
          scroll={{ x: 1329 }}
          locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={failed ? '列表不可用' : '暂无 API Key'} /> }}
          pagination={{ current: query.page, pageSize: query.pageSize, total, showSizeChanger: true, showTotal: (count) => `共 ${count} 个`, onChange: (page, pageSize) => setQuery({ page, pageSize }) }}
        />
      </Flex>
      {createOpen && permissions && (
        <CreateKeyModal permissions={permissions} onClose={() => setCreateOpen(false)} onCreated={(result) => {
          setCreateOpen(false);
          setCreated(result);
          setFeedback(undefined);
          if (query.page === 1) reload();
          else setQuery((value) => ({ ...value, page: 1 }));
        }} />
      )}
      {created && (
        <Modal title="API Key 已创建" open onCancel={() => setCreated(undefined)} onOk={() => setCreated(undefined)} cancelButtonProps={{ style: { display: 'none' } }} okText="关闭" mask={{ closable: false }}>
          <Flex vertical gap={16}>
            <Alert showIcon type="warning" title="明文仅在本次显示，请先复制并保存到客户端的安全配置。" />
            <McpCopyBlock label="API Key" value={created.secret} />
            <McpCopyBlock label="接入指令" value={instructions} />
          </Flex>
        </Modal>
      )}
      {inspected && (
        <Modal title="API Key 权限" open onCancel={() => setInspected(undefined)} footer={null}>
          <Descriptions size="small" column={1} bordered items={[
            { key: 'name', label: '名称', children: inspected.name },
            { key: 'id', label: 'Key ID', children: <Typography.Text code>{inspected.id}</Typography.Text> },
            { key: 'access', label: '授权模式', children: accessLabels[inspected.access] },
            { key: 'permissions', label: '工具权限', children: <Space wrap>{inspected.permissionIds.map((id) => <Tag key={id} title={id}>{permissionNames.get(id) ?? id}</Tag>)}</Space> },
            { key: 'instances', label: '可管理实例', children: inspected.instanceIds.length ? <Space wrap>{inspected.instanceIds.map((id) => <Tag key={id} title={id}>{instanceNames.get(id) ?? id}</Tag>)}</Space> : '—' },
            { key: 'revoked', label: '吊销时间', children: formatMcpTime(inspected.revokedAtUtc) },
          ]} />
        </Modal>
      )}
      {instructionsOpen && (
        <Modal title="MCP 接入指令" open onCancel={() => setInstructionsOpen(false)} footer={null}>
          <Typography.Paragraph type="secondary">系统剪贴板不可用时，可以选中文本手动复制。</Typography.Paragraph>
          <McpCopyBlock label="接入指令" value={instructions} />
        </Modal>
      )}
    </Card>
  );
}

function CreateKeyModal({ permissions, onClose, onCreated }: { permissions: McpPermissions; onClose: () => void; onCreated: (created: McpKeyCreated) => void }) {
  const [form] = Form.useForm<{ name: string; expiresAt?: string; access: McpAccess }>();
  const access = Form.useWatch('access', form) ?? 'ReadOnly';
  const [selected, setSelected] = useState<string[]>([]);
  const [instanceIds, setInstanceIds] = useState<string[]>([]);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const tools = new Map(permissions.groups.flatMap((group) => group.tools.map((tool) => [tool.id, tool])));
  const needsInstances = selected.some((id) => tools.get(id)?.requiresInstanceScope);
  const tree = permissions.groups.map((group) => ({
    key: `group:${group.id}`,
    title: group.label,
    disableCheckbox: group.tools.every((tool) => access === 'ReadOnly' && tool.access === 'ReadWrite'),
    children: group.tools.map((tool) => ({
      key: tool.id,
      disableCheckbox: access === 'ReadOnly' && tool.access === 'ReadWrite',
      title: <Space size={4}><span title={tool.description}>{tool.label}</span>{tool.access === 'ReadWrite' && <Tag color="blue">写入</Tag>}</Space>,
    })),
  }));

  const submit = async ({ name, expiresAt, access: selectedAccess }: { name: string; expiresAt?: string; access: McpAccess }) => {
    const expiresAtUtc = beijingTimeToUtc(expiresAt);
    if (expiresAt && (!expiresAtUtc || Date.parse(expiresAtUtc) <= Date.now())) {
      setError('请选择晚于当前时间的有效期。');
      return;
    }
    if (!selected.length) {
      setError('至少勾选一项工具权限。');
      return;
    }
    if (needsInstances && !instanceIds.length) {
      setError('请至少选择一个允许管理的已有实例。');
      return;
    }
    setSaving(true);
    setError('');
    try {
      const response = await createMcpKey({ name: name.trim(), access: selectedAccess, permissionIds: selected, instanceIds: needsInstances ? instanceIds : [], expiresAtUtc });
      if (!response.success || !response.data) throw response;
      onCreated(response.data);
    } catch (failure) {
      setError(reportApiError(failure, '创建 API Key 失败，请检查授权范围或稍后重试。'));
    } finally {
      setSaving(false);
    }
  };

  return (
    <Modal title="新建 API Key" open width={620} onCancel={() => !saving && onClose()} onOk={() => form.submit()} okText="创建" cancelText="取消" confirmLoading={saving} mask={{ closable: !saving }}>
      <Form form={form} layout="vertical" initialValues={{ access: 'ReadOnly' }} disabled={saving} onFinish={submit}>
        {error && <Alert type="error" showIcon title={error} style={{ marginBottom: 16 }} />}
        <Form.Item name="name" label="名称" rules={[{ required: true, whitespace: true, max: 100, message: '请输入 1–100 字符的名称。' }]}>
          <Input autoComplete="off" maxLength={100} />
        </Form.Item>
        <Form.Item name="access" label="授权模式">
          <Radio.Group options={[{ value: 'ReadOnly', label: '只读' }, { value: 'ReadWrite', label: '读写' }]} onChange={(event) => {
            if (event.target.value !== 'ReadOnly') return;
            setSelected((current) => current.filter((id) => tools.get(id)?.access === 'ReadOnly'));
            setInstanceIds([]);
          }} />
        </Form.Item>
        <Form.Item name="expiresAt" label="有效期（北京时间）" extra="留空为永久有效。">
          <Input type="datetime-local" />
        </Form.Item>
        <Form.Item label="工具权限" required extra={`已勾选 ${selected.length} 项`}>
          <div className="mcp-permission-tree">
            <Tree checkable selectable={false} defaultExpandAll disabled={saving} checkedKeys={selected} treeData={tree} onCheck={(checked) => {
              const ids = (Array.isArray(checked) ? checked : checked.checked).map(String).filter((id) => {
                const tool = tools.get(id);
                return tool && (access === 'ReadWrite' || tool.access === 'ReadOnly');
              });
              setSelected(ids);
              if (!ids.some((id) => tools.get(id)?.requiresInstanceScope)) setInstanceIds([]);
            }} />
          </div>
        </Form.Item>
        {needsInstances && (
          <Form.Item label="可管理实例" required extra="启动或设置自动启动时，会校验创建 Key 时获准的绑定配置。">
            <Select aria-label="可管理实例" mode="multiple" maxCount={100} value={instanceIds} onChange={setInstanceIds} options={permissions.instances.map((instance) => ({ value: instance.id, label: instance.name }))} placeholder="选择已有实例" />
          </Form.Item>
        )}
      </Form>
    </Modal>
  );
}
