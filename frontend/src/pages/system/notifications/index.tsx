import { MailOutlined, SafetyCertificateOutlined, SendOutlined } from '@ant-design/icons';
import { Link, useAccess } from '@umijs/max';
import { Alert, Button, Card, Checkbox, Col, Form, Input, InputNumber, Modal, Row, Select, Space, Spin, Switch, Tabs, Tag, Typography } from 'antd';
import { useEffect, useState } from 'react';
import { defaultNotificationSettings, getNotificationSettings, type NotificationSettings, type NotificationTaskResult, saveNotificationSettings, sendTestEmail } from '@/services/honeypot/notifications';
import { formatReportTime, parseRecipients, reportApiError } from '@/utils/reportFormat';

interface SettingsForm extends Omit<NotificationSettings, 'defaultRecipients' | 'schedules'> {
  defaultRecipientsText: string; authorizationCode?: string;
  schedules: (NotificationSettings['schedules'][number] & { recipientsText: string })[];
}
const toForm = (settings: NotificationSettings): SettingsForm => ({ ...settings, authorizationCode: '', defaultRecipientsText: settings.defaultRecipients.join(', '), schedules: settings.schedules.map((schedule) => ({ ...schedule, recipientsText: schedule.recipients.join(', ') })) });
const optionalEmails = [{ validator: (_: unknown, value?: string) => parseRecipients(value ?? '').length <= 20 && parseRecipients(value ?? '').every((email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) ? Promise.resolve() : Promise.reject(new Error('请输入有效邮箱，多个地址用逗号分隔，最多 20 位收件人')) }];
const scheduleDescription: Record<string, { title: string; detail: string }> = { Daily: { title: '日报', detail: '每天发送上一完整自然日的运行报告' }, Weekly: { title: '周报', detail: '每周一发送上周一至周日的运行报告' }, Monthly: { title: '月报', detail: '每月一日发送上一完整自然月的运行报告' } };

export default function NotificationSettingsPage() {
  const access = useAccess();
  return access.canAdmin ? <NotificationSettingsContent /> : <Alert type="error" title="仅管理员可访问通知设置。" />;
}

function NotificationSettingsContent() {
  const [form] = Form.useForm<SettingsForm>();
  const [testForm] = Form.useForm<{ recipient: string }>();
  const [settings, setSettings] = useState<NotificationSettings>();
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [loadFailed, setLoadFailed] = useState(false);
  const [reload, setReload] = useState(0);
  const [feedback, setFeedback] = useState<{ type: 'success' | 'error'; text: string }>();
  const [testOpen, setTestOpen] = useState(false);
  const [testing, setTesting] = useState(false);
  const [task, setTask] = useState<NotificationTaskResult>();
  const useSsl = Form.useWatch('useSsl', form) ?? true;
  const enabled = Form.useWatch('enabled', form);

  useEffect(() => {
    let active = true;
    const controller = new AbortController();
    setLoading(true); setLoadFailed(false);
    void getNotificationSettings(controller.signal).then((response) => {
      if (!active) return;
      if (!response.success || !response.data) throw new Error('Settings unavailable');
      setSettings(response.data); form.setFieldsValue(toForm(response.data));
    }).catch(() => { if (active) setLoadFailed(true); }).finally(() => { if (active) setLoading(false); });
    return () => { active = false; controller.abort(); };
  }, [form, reload]);

  const save = async (values: SettingsForm) => {
    if (!settings) return;
    setSaving(true); setFeedback(undefined);
    const { defaultRecipientsText, authorizationCode, schedules, ...plain } = values;
    const next: NotificationSettings = { ...settings, ...plain, securityMode: plain.useSsl ? (plain.securityMode === 'StartTls' ? 'StartTls' : 'SslOnConnect') : 'None', host: plain.host?.trim() ?? '', fromEmail: plain.fromEmail?.trim() ?? '', username: plain.username?.trim() || plain.fromEmail?.trim() || '', defaultRecipients: parseRecipients(defaultRecipientsText ?? ''), schedules: schedules.map(({ recipientsText, ...schedule }) => ({ ...schedule, recipients: parseRecipients(recipientsText ?? '') })) };
    try {
      const response = await saveNotificationSettings(next, authorizationCode);
      if (!response.success || !response.data) throw response;
      setSettings(response.data); form.setFieldsValue(toForm(response.data));
      setFeedback({ type: 'success', text: '通知设置已保存。' });
    } catch (error) { setFeedback({ type: 'error', text: reportApiError(error, '设置保存失败，请检查字段、收件人和管理员权限。') }); }
    finally { setSaving(false); }
  };
  const test = async ({ recipient }: { recipient: string }) => {
    setTesting(true); setFeedback(undefined);
    try {
      const response = await sendTestEmail(recipient.trim());
      if (!response.success || !response.data) throw response;
      setTask(response.data); setTestOpen(false); testForm.resetFields();
      setFeedback({ type: 'success', text: '测试邮件已加入队列，发送结果请查看邮件记录。' });
    } catch (error) { setFeedback({ type: 'error', text: reportApiError(error, '测试邮件未能加入队列，请先保存有效配置并检查发送频率限制。') }); }
    finally { setTesting(false); }
  };

  return <Space orientation="vertical" size={20} style={{ display: 'flex' }}>
    <div><Typography.Title level={3}>通知设置</Typography.Title><Typography.Paragraph type="secondary">配置邮件服务与日报、周报、月报订阅，及时了解蜜罐运行情况。</Typography.Paragraph></div>
    {loadFailed && <Alert type="error" showIcon title="无法读取通知设置，已暂停保存。" action={<Button size="small" onClick={() => setReload((value) => value + 1)}>重试</Button>} />}
    {feedback && <Alert type={feedback.type} showIcon title={feedback.text} />}
    {task && <Alert type="info" title={<Space wrap><span>任务：{task.deliveryIds.join('、')}</span><Link to={`/system/mail-records?status=all&id=${encodeURIComponent(task.deliveryIds[0] ?? '')}`}>查看邮件记录</Link></Space>} />}
    <Spin spinning={loading}>
      <Form form={form} layout="vertical" initialValues={toForm(defaultNotificationSettings)} onFinish={save} disabled={loading || saving || loadFailed}>
        <Card style={{ marginBottom: 20 }}><Row justify="space-between" align="middle"><Col><Space><MailOutlined style={{ fontSize: 24 }} /><div><Typography.Text strong>邮件通知总开关</Typography.Text><div><Typography.Text type="secondary">控制邮件发送。各类定时报表还需单独启用。</Typography.Text></div></div></Space></Col><Col><Form.Item name="enabled" valuePropName="checked" style={{ marginBottom: 0 }}><Switch checkedChildren="开启" unCheckedChildren="关闭" /></Form.Item></Col></Row></Card>
        <Tabs items={[
          { key: 'server', label: '邮件服务器', forceRender: true, children: <Row gutter={[20, 20]}><Col xs={24} xl={15}><Card title="SMTP 连接与发件身份"><Row gutter={20}>
            <Col xs={24} sm={17}><Form.Item name="host" label="邮件服务器地址" rules={[{ required: Boolean(enabled), message: '请输入邮件服务器地址' }, { max: 253 }, { validator: (_, value?: string) => !value || !/[\s/?#@]/.test(value) && !value.includes('://') ? Promise.resolve() : Promise.reject(new Error('仅填写域名或 IP，不包含协议、端口和路径')) }]}><Input placeholder="smtp.example.com" autoComplete="off" /></Form.Item></Col>
            <Col xs={24} sm={7}><Form.Item name="port" label="端口" rules={[{ required: true }, { type: 'integer', min: 1, max: 65535 }]}><InputNumber min={1} max={65535} precision={0} style={{ width: '100%' }} /></Form.Item></Col>
            <Col span={24}><Form.Item name="useSsl" valuePropName="checked"><Checkbox onChange={(event) => { if (event.target.checked && form.getFieldValue('securityMode') === 'None') form.setFieldValue('securityMode', 'SslOnConnect'); }}>启用 SSL/TLS 加密（推荐）</Checkbox></Form.Item></Col>
            <Col span={24}>{useSsl ? <Form.Item name="securityMode" label="加密方式" rules={[{ required: true }]}><Select options={[{ value: 'SslOnConnect', label: 'SSL/TLS 直连（常用端口 465）' }, { value: 'StartTls', label: 'STARTTLS 升级（常用端口 587）' }]} /></Form.Item> : <Alert type="warning" showIcon title="当前为未加密 SMTP，授权码及邮件内容可能以明文传输。" style={{ marginBottom: 24 }} />}</Col>
            <Col xs={24} sm={12}><Form.Item name="fromEmail" label="发件邮箱地址" rules={[{ required: Boolean(enabled), message: '请输入发件邮箱' }, { type: 'email', message: '邮箱格式不正确' }]}><Input placeholder="honeypot@example.com" autoComplete="off" /></Form.Item></Col>
            <Col xs={24} sm={12}><Form.Item name="fromName" label="发件人名称" rules={[{ max: 100 }]}><Input placeholder="通研 Honeypot" /></Form.Item></Col>
            <Col xs={24} sm={12}><Form.Item name="username" label="SMTP 登录账号" extra="留空时使用发件邮箱地址。"><Input placeholder="默认同发件邮箱" autoComplete="off" /></Form.Item></Col>
            <Col xs={24} sm={12}><Form.Item name="authorizationCode" label="邮箱授权码" extra={settings?.hasCredential ? '授权码已配置，留空保留原值。' : '请输入邮箱服务商提供的 SMTP 授权码。'}><Input.Password placeholder={settings?.hasCredential ? '已配置，留空保留' : '请输入授权码'} autoComplete="new-password" /></Form.Item></Col>
            <Col span={24}><Form.Item name="defaultRecipientsText" label="默认收件人" rules={optionalEmails} extra="多个邮箱用逗号分隔，报表未单独填写收件人时使用此列表。"><Input.TextArea rows={2} placeholder="admin@example.com, security@example.com" /></Form.Item></Col>
            <Col span={24}><Form.Item name="timeoutSeconds" label="连接超时（秒）" rules={[{ required: true }, { type: 'integer', min: 5, max: 60 }]}><InputNumber min={5} max={60} /></Form.Item></Col>
          </Row></Card></Col><Col xs={24} xl={9}><Card title={<Space><SafetyCertificateOutlined />发送频率限制</Space>}><Typography.Paragraph type="secondary">所有发送任务统一执行限流；测试和重试还需满足冷却时间。</Typography.Paragraph>
            <Form.Item name="maxPerHour" label="每小时最多发送（封）" rules={[{ required: true }, { type: 'integer', min: 1, max: 1000 }]}><InputNumber min={1} max={1000} style={{ width: '100%' }} /></Form.Item>
            <Form.Item name="maxPerRecipientPerHour" label="每个收件人每小时最多（封）" rules={[{ required: true }, { type: 'integer', min: 1, max: 1000 }]}><InputNumber min={1} max={1000} style={{ width: '100%' }} /></Form.Item>
            <Form.Item name="testCooldownSeconds" label="测试发送冷却（秒）" rules={[{ required: true }, { type: 'integer', min: 10, max: 3600 }]}><InputNumber min={10} max={3600} style={{ width: '100%' }} /></Form.Item>
            <Form.Item name="resendCooldownSeconds" label="重新发送冷却（秒）" rules={[{ required: true }, { type: 'integer', min: 10, max: 3600 }]}><InputNumber min={10} max={3600} style={{ width: '100%' }} /></Form.Item>
            <Typography.Text type="secondary">授权码仅写入后端受控存储，不会从查询接口回显。</Typography.Text>
          </Card></Col></Row> },
          { key: 'schedules', label: '报告订阅', forceRender: true, children: <><Alert type="info" showIcon title="定时报表发送上一完整周期，时间统一为北京时间。" description="日报每天执行；周报固定周一；月报固定每月一日。请先开启邮件通知总开关。" style={{ marginBottom: 20 }} /><Row gutter={[20, 20]}>{(settings?.schedules ?? defaultNotificationSettings.schedules).map((schedule, index) => <Col key={schedule.kind} xs={24} xl={8}><Card title={scheduleDescription[schedule.kind]?.title ?? schedule.kind} extra={<Form.Item name={['schedules', index, 'enabled']} valuePropName="checked" style={{ margin: 0 }}><Switch /></Form.Item>} style={{ height: '100%' }}><Typography.Paragraph type="secondary">{scheduleDescription[schedule.kind]?.detail}</Typography.Paragraph>
            <Form.Item name={['schedules', index, 'kind']} hidden><Input /></Form.Item>
            <Form.Item name={['schedules', index, 'sendTime']} label="发送时间" rules={[{ required: true, message: '请选择发送时间' }, { pattern: /^([01]\d|2[0-3]):[0-5]\d$/, message: '请输入 HH:mm 格式' }]}><Input type="time" /></Form.Item>
            <Form.Item name={['schedules', index, 'recipientsText']} label="收件人" rules={optionalEmails} extra="留空使用默认收件人。"><Input.TextArea rows={3} placeholder="默认收件人" /></Form.Item>
            <Space orientation="vertical" size={8}><Typography.Text type="secondary">下次执行：{formatReportTime(schedule.nextRunAtUtc)}</Typography.Text><Typography.Text type="secondary">上次执行：{formatReportTime(schedule.lastRunAtUtc)}</Typography.Text>{schedule.lastRunStatus && <Tag color={schedule.lastRunStatus === 'Failed' ? 'error' : 'processing'}>{schedule.lastRunStatus === 'Queued' ? '已加入发送队列' : schedule.lastRunStatus === 'Failed' ? '执行失败' : schedule.lastRunStatus}</Tag>}<Link to="/reports">查看运行报告</Link></Space>
          </Card></Col>)}</Row></> },
        ]} />
        <Card style={{ marginTop: 20 }}><Space wrap><Button type="primary" htmlType="submit" loading={saving}>保存通知设置</Button><Button icon={<SendOutlined aria-hidden />} disabled={!settings || loadFailed || loading || saving} onClick={() => { setTestOpen(true); testForm.setFieldValue('recipient', settings?.defaultRecipients[0] ?? ''); }}>测试发送邮件</Button><Link to="/system/mail-records">查看邮件记录</Link></Space><Typography.Paragraph type="secondary" style={{ marginTop: 12, marginBottom: 0 }}>测试发送仅使用已保存配置；修改表单后请先保存。</Typography.Paragraph></Card>
      </Form>
    </Spin>
    <Modal title="测试发送邮件" open={testOpen} onCancel={() => !testing && setTestOpen(false)} footer={null} destroyOnHidden><Typography.Paragraph type="secondary">使用已保存配置 {settings?.host}:{settings?.port}，不会使用表单中未保存的修改。测试不受通知总开关影响。入队后请在邮件记录查看发送结果。</Typography.Paragraph><Form form={testForm} layout="vertical" onFinish={test}><Form.Item name="recipient" label="测试收件人" rules={[{ required: true, message: '请输入收件人' }, { type: 'email', message: '请输入有效邮箱地址' }]}><Input placeholder="admin@example.com" /></Form.Item><Button type="primary" htmlType="submit" loading={testing}>提交测试邮件</Button></Form></Modal>
  </Space>;
}
