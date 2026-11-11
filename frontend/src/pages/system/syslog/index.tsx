import { PlusOutlined } from '@ant-design/icons';
import { useAccess } from '@umijs/max';
import { Alert, Button, Card, Checkbox, Collapse, Form, Input, InputNumber, Select, Space, Spin, Switch, Table, Tag, Typography } from 'antd';
import { useEffect, useState } from 'react';
import { defaultSyslogSettings, getSyslogSettings, getSyslogStatus, saveSyslogSettings, syslogProtocolPorts, syslogTestMessageLimit, testSyslogTarget, type SyslogDeliveryStatus, type SyslogProtocol, type SyslogSettings, type SyslogSettingsSnapshot, type SyslogTargetStatus } from '@/services/honeypot/syslog';
import { formatReportTime, reportApiError } from '@/utils/reportFormat';

const protocolLabels = { Udp: 'UDP', Tcp: 'TCP', Tls: 'TLS', Relp: 'RELP' };
const stateLabels: Record<string, string> = { Disabled: '已禁用', Waiting: '等待发送', Connecting: '连接中', Available: '可发送', Ready: '可发送', Backoff: '等待重试', BackingOff: '等待重试', Faulted: '故障', Paused: '积压已暂停', LocalSubmitted: 'UDP 本地提交' };
const stageLabels: Record<string, string> = { LocalSubmitted: 'UDP 已本地提交，无法确认接收', Written: '已写入传输流，未确认远端持久化', Acknowledged: 'RELP 已应答，持久化由接收端决定', Failed: '发送失败' };

function createTargetId() {
  // 内网管理台可能通过 HTTP 打开，getRandomValues 在该环境也可用。
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return `target-${Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')}`;
}

export default function SyslogPage() {
  const access = useAccess();
  return access.canAdmin ? <SyslogSettingsContent /> : <Alert type="error" title="仅管理员可访问 Syslog 配置。" />;
}

function SyslogSettingsContent() {
  const [form] = Form.useForm<SyslogSettings>();
  const [snapshot, setSnapshot] = useState<SyslogSettingsSnapshot>();
  const [status, setStatus] = useState<SyslogDeliveryStatus>();
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [loadFailed, setLoadFailed] = useState(false);
  const [statusFailed, setStatusFailed] = useState(false);
  const [reload, setReload] = useState(0);
  const [testTargetId, setTestTargetId] = useState<string>();
  const [testMessage, setTestMessage] = useState('');
  const [testing, setTesting] = useState(false);
  const [testFeedback, setTestFeedback] = useState<{ type: 'success' | 'error'; text: string }>();
  const [feedback, setFeedback] = useState<{ type: 'success' | 'error' | 'warning'; text: string }>();
  const targets = Form.useWatch('targets', form) ?? [];
  const savedTargets = snapshot?.settings.targets ?? [];
  const testTarget = testTargetId
    ? savedTargets.find((target) => target.id === testTargetId)
    : savedTargets.length === 1 ? savedTargets[0] : undefined;
  const testUnavailable = loading || loadFailed || saving || testing || Boolean(snapshot?.configFault);

  useEffect(() => {
    let active = true;
    const controller = new AbortController();
    setLoading(true); setLoadFailed(false);
    void getSyslogSettings(controller.signal).then((response) => {
      if (!active) return;
      if (!response.success || !response.data) throw new Error('Settings unavailable');
      setSnapshot(response.data); form.setFieldsValue(response.data.settings);
    }).catch(() => { if (active) setLoadFailed(true); }).finally(() => { if (active) setLoading(false); });
    return () => { active = false; controller.abort(); };
  }, [form, reload]);

  useEffect(() => {
    let active = true;
    const controller = new AbortController();
    const refresh = async () => {
      try {
        const response = await getSyslogStatus(controller.signal);
        if (active && response.success && response.data) { setStatus(response.data); setStatusFailed(false); }
        else if (active) setStatusFailed(true);
      } catch { if (active) setStatusFailed(true); }
    };
    void refresh();
    const timer = window.setInterval(() => { if (document.visibilityState !== 'hidden') void refresh(); }, 10000);
    return () => { active = false; controller.abort(); window.clearInterval(timer); };
  }, [reload]);

  const save = async (values: SyslogSettings) => {
    if (!snapshot) return;
    setSaving(true); setFeedback(undefined);
    try {
      // 显式投影当前字段，旧配置中的严重级别和 Facility 不随表单保存。
      const response = await saveSyslogSettings({ ...values, targets: values.targets.map((target) => ({
        id: target.id,
        name: target.name.trim(),
        host: target.host.trim(),
        port: target.port,
        protocol: target.protocol,
        enabled: target.enabled,
        ignoreSslErrors: target.protocol === 'Tls' && target.ignoreSslErrors,
      })) }, snapshot.revision);
      if (!response.success || !response.data) throw response;
      setSnapshot(response.data); form.setFieldsValue(response.data.settings);
      setFeedback({ type: 'success', text: 'Syslog 配置已保存并生效；保存结果不代表远端已经收到日志。' });
    } catch (error) { setFeedback({ type: 'error', text: reportApiError(error, '配置保存失败，请检查字段、版本和目录权限。') }); }
    finally { setSaving(false); }
  };
  const sendTestMessage = async () => {
    if (!testTarget || testUnavailable || testMessage.length > syslogTestMessageLimit) return;
    setTesting(true);
    setTestFeedback(undefined);
    try {
      const response = await testSyslogTarget(testTarget.id, testMessage.trim() || undefined);
      if (!response.success || !response.data) throw response;
      const result = response.data;
      const stage = result.errorCode === 'SYSLOG_TEST_MESSAGE_TOO_LONG'
        ? '消息超出当前协议的报文长度，请缩短后重试'
        : stageLabels[result.stage] ?? result.stage;
      setTestFeedback({ type: result.succeeded ? 'success' : 'error', text: `${stage}。关联 ID：${result.correlationId}${result.errorCode ? `，错误码：${result.errorCode}` : ''}` });
    } catch (error) { setTestFeedback({ type: 'error', text: reportApiError(error, '测试失败，请检查服务器地址、协议及证书。') }); }
    finally { setTesting(false); }
  };

  return <Space orientation="vertical" size={20} style={{ display: 'flex' }}>
    <div><Typography.Title level={3}>Syslog 配置</Typography.Title><Typography.Paragraph type="secondary">按级别转发本机通研蜜罐各模块的运行、业务与安全审计日志。</Typography.Paragraph></div>
    <Alert type="info" showIcon title="默认关闭，启用后转发新日志" description="最多配置 3 个独立目标。主机名由服务器自动生成，应用名按模块区分；日志不包含密码、认证材料或请求响应正文。" />
    <Card size="small"><Typography.Text>主机名：<Typography.Text code>{snapshot?.hostname ?? '读取中'}</Typography.Text></Typography.Text><Typography.Paragraph type="secondary" style={{ marginBottom: 0 }}>应用名示例：honeypot-runtime、honeypot-ssh、honeypot-evidence。</Typography.Paragraph></Card>
    {loadFailed && <Alert type="error" title="无法读取配置，已暂停保存。" action={<Button onClick={() => setReload((value) => value + 1)}>重新读取</Button>} />}
    {snapshot?.configFault && <Alert type="error" title="原配置不可读取，外发已关闭且原文件保留。" description="请管理员修复配置后重启服务；页面不会覆盖不可读取的配置。" />}
    {feedback && <Alert type={feedback.type} showIcon title={feedback.text} />}
    <Spin spinning={loading}><Form form={form} layout="vertical" initialValues={defaultSyslogSettings} onFinish={save} disabled={loading || saving || loadFailed || Boolean(snapshot?.configFault)}>
      <Card style={{ marginBottom: 20 }}><Form.Item name="enabled" label="启用 Syslog" valuePropName="checked" style={{ marginBottom: 0 }}><Switch checkedChildren="开启" unCheckedChildren="关闭" /></Form.Item></Card>
      <Form.List name="targets" rules={[{ validator: async (_, values) => { if (form.getFieldValue('enabled') && !values?.some((value: { enabled: boolean }) => value.enabled)) throw new Error('启用 Syslog 至少需要一个启用的目标'); } }]}>{(fields, { add, remove }, { errors }) => <Space orientation="vertical" size={16} style={{ display: 'flex' }}>
        {fields.map((field) => {
          const target = targets[field.name];
          return <Card key={field.key} title={`目标 ${field.name + 1}`} extra={<Button danger onClick={() => remove(field.name)}>移除目标</Button>}>
            <Form.Item name={[field.name, 'id']} hidden><Input /></Form.Item>
            <Space align="start" size="large" wrap>
              <Form.Item name={[field.name, 'name']} label={`目标 ${field.name + 1} 名称`} rules={[{ required: true, whitespace: true, max: 64 }]}><Input style={{ width: 240 }} placeholder="日志服务器" /></Form.Item>
              <Form.Item name={[field.name, 'enabled']} label="启用此目标" valuePropName="checked"><Switch /></Form.Item>
            </Space>
            <Space align="start" size="large" wrap>
              <Form.Item name={[field.name, 'host']} label={`服务器地址 ${field.name + 1}`} extra="仅填写域名、IPv4 或 IPv6，不含协议、端口、路径。" rules={[{ required: true, whitespace: true, max: 253 }]}><Input style={{ width: 320 }} placeholder="syslog.example.com" /></Form.Item>
              <Form.Item name={[field.name, 'protocol']} label={`协议 ${field.name + 1}`} rules={[{ required: true }]}><Select style={{ width: 120 }} options={Object.entries(protocolLabels).map(([value, label]) => ({ value, label }))} onChange={(protocol: SyslogProtocol) => {
                const previous = target?.protocol ?? 'Tls';
                const port = form.getFieldValue(['targets', field.name, 'port']);
                if (port === syslogProtocolPorts[previous]) form.setFieldValue(['targets', field.name, 'port'], syslogProtocolPorts[protocol]);
                form.setFieldValue(['targets', field.name, 'ignoreSslErrors'], false);
              }} /></Form.Item>
              <Form.Item name={[field.name, 'port']} label={`端口 ${field.name + 1}`} rules={[{ required: true }, { type: 'integer', min: 1, max: 65535 }]}><InputNumber min={1} max={65535} precision={0} /></Form.Item>
            </Space>
            {target?.protocol === 'Tls' && <Form.Item name={[field.name, 'ignoreSslErrors']} valuePropName="checked"><Checkbox>忽略 SSL 错误</Checkbox></Form.Item>}
            {target?.protocol === 'Tls' && target.ignoreSslErrors && <Alert type="warning" showIcon title="未验证服务器身份" description="仅此目标跳过证书错误检查；传输仍使用 TLS。" style={{ marginBottom: 16 }} />}
            {target?.protocol === 'Relp' && <Alert type="info" title="RELP 使用 TCP 并等待应答，不提供加密。" style={{ marginBottom: 16 }} />}
          </Card>;
        })}
        <Form.ErrorList errors={errors} />
        <Button icon={<PlusOutlined />} disabled={fields.length >= 3 || loading || saving || loadFailed || Boolean(snapshot?.configFault)} onClick={() => add({ id: createTargetId(), name: `日志服务器 ${fields.length + 1}`, host: '', port: 6514, protocol: 'Tls', enabled: true, ignoreSslErrors: false })}>添加目标</Button>
      </Space>}</Form.List>
      <Collapse style={{ marginTop: 20 }} items={[{ key: 'advanced', label: '超时与缓存限制', children: <Space align="start" size="large" wrap>
        <Form.Item name="connectTimeoutSeconds" label="连接超时（秒）" rules={[{ required: true }, { type: 'integer', min: 1, max: 60 }]}><InputNumber min={1} max={60} /></Form.Item>
        <Form.Item name="writeTimeoutSeconds" label="写入超时（秒）" rules={[{ required: true }, { type: 'integer', min: 1, max: 60 }]}><InputNumber min={1} max={60} /></Form.Item>
        <Form.Item name="queueCapacity" label="入口队列上限（条）" rules={[{ required: true }, { type: 'integer', min: 100, max: 100000 }]}><InputNumber min={100} max={100000} /></Form.Item>
        <Form.Item name="spoolMaxBytes" label="每目标暂存上限（字节）" rules={[{ required: true }, { type: 'integer', min: 1048576, max: 1073741824 }]}><InputNumber min={1048576} max={1073741824} style={{ width: 180 }} /></Form.Item>
        <Form.Item name="retentionHours" label="暂存保留（小时）" rules={[{ required: true }, { type: 'integer', min: 1, max: 168 }]}><InputNumber min={1} max={168} /></Form.Item>
      </Space> }]} />
      <Space style={{ marginTop: 20 }}><Button type="primary" htmlType="submit" loading={saving}>保存 Syslog 配置</Button><Button onClick={() => setReload((value) => value + 1)}>重新读取</Button></Space>
    </Form></Spin>
    <Card title="测试消息">
      <Form layout="vertical" onFinish={sendTestMessage}>
        <Form.Item label="测试目标" htmlFor="syslog-test-target">
          <Select
            id="syslog-test-target"
            value={testTarget?.id}
            onChange={(targetId) => { setTestTargetId(targetId); setTestFeedback(undefined); }}
            disabled={testUnavailable || savedTargets.length === 0}
            placeholder={savedTargets.length === 0 ? '请先保存一个目标' : '选择已保存的目标'}
            options={savedTargets.map((target) => ({ value: target.id, label: `${target.name}（${protocolLabels[target.protocol]} ${target.host}:${target.port}）` }))}
          />
        </Form.Item>
        <Form.Item label="消息内容" htmlFor="syslog-test-message">
          <Input
            id="syslog-test-message"
            value={testMessage}
            onChange={(event) => setTestMessage(event.target.value)}
            disabled={testUnavailable}
            placeholder="留空发送默认测试消息"
            maxLength={syslogTestMessageLimit}
            showCount
          />
        </Form.Item>
        <Space orientation="vertical" style={{ display: 'flex' }}>
          <Button type="primary" htmlType="submit" loading={testing} disabled={testUnavailable || !testTarget}>发送测试消息</Button>
          {testFeedback && <Alert type={testFeedback.type} showIcon title={testFeedback.text} />}
        </Space>
      </Form>
    </Card>
    <Card title="已保存目标的发送状态" extra={<Button onClick={() => setReload((value) => value + 1)}>刷新</Button>}>
      {statusFailed && <Alert type="warning" title="状态刷新失败，以下数据可能不是最新状态。" style={{ marginBottom: 16 }} />}
      {Boolean(status?.pausedPendingCount || status?.discardedPausedCount) && <Alert type="info" title={`旧目标或禁用目标的暂停积压：${status?.pausedPendingCount ?? 0} 条；因过期或容量限制丢弃：${status?.discardedPausedCount ?? 0} 条。`} description="更改目标地址或协议后，旧日志不会自动发送到新目标。" style={{ marginBottom: 16 }} />}
      <Table<SyslogTargetStatus> rowKey="targetId" pagination={false} scroll={{ x: 1000 }} dataSource={status?.targets ?? []} columns={[
        { title: '目标', dataIndex: 'targetId', render: (id: string) => snapshot?.settings.targets.find((target) => target.id === id)?.name ?? id },
        { title: '状态', dataIndex: 'state', render: (state: string) => <Tag>{stateLabels[state] ?? state}</Tag> },
        { title: '待发送', dataIndex: 'pendingCount' }, { title: '已提交/写入', dataIndex: 'sentCount' }, { title: 'RELP 应答', dataIndex: 'confirmedCount' },
        { title: '失败/重试', render: (_, row) => `${row.failedCount}/${row.retriedCount}` }, { title: '丢弃/截断', render: (_, row) => `${row.droppedCount}/${row.truncatedCount}` },
        { title: '最近发送', dataIndex: 'lastSentAtUtc', render: (time?: string) => formatReportTime(time) },
        { title: '错误码', dataIndex: 'lastErrorCode', render: (code?: string) => code ?? '—' },
      ]} />
    </Card>
  </Space>;
}
