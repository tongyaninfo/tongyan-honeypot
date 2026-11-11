import { Alert, Button, Card, Form, Input, InputNumber, Select, Space, Spin, Switch, Typography } from 'antd';
import { useEffect, useState } from 'react';
import { defaultIPLocationSettings, getIPLocationSettings, type IPLocationSettings, saveIPLocationSettings } from '@/services/honeypot/api';
import { ipLocationClient } from '@/services/honeypot/ipLocationClient';

const databases = ['CZ88', 'ip2location', 'ip2region', 'dbip', 'ipinfo', 'geolite2'];

export default function IPLocationSettingsPage() {
  const [form] = Form.useForm<IPLocationSettings>();
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [loadFailed, setLoadFailed] = useState(false);
  const [feedback, setFeedback] = useState<{ type: 'success' | 'error'; text: string }>();
  const [reload, setReload] = useState(0);

  useEffect(() => {
    let active = true;
    const controller = new AbortController();
    setLoading(true);
    setLoadFailed(false);
    void getIPLocationSettings({ signal: controller.signal })
      .then((response) => {
        if (!active) return;
        if (!response.success || !response.data) throw new Error('Settings unavailable');
        form.setFieldsValue(response.data);
      })
      .catch(() => { if (active) setLoadFailed(true); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; controller.abort(); };
  }, [form, reload]);

  const save = async (values: IPLocationSettings) => {
    setSaving(true);
    setFeedback(undefined);
    try {
      const response = await saveIPLocationSettings({ ...values, host: values.host.trim() });
      if (!response.success || !response.data) throw new Error('Settings unavailable');
      form.setFieldsValue(response.data);
      ipLocationClient.invalidate();
      setFeedback({ type: 'success', text: 'IP 数据库配置已保存。' });
    } catch {
      setFeedback({ type: 'error', text: '配置保存失败，请检查配置与管理员权限后重试。' });
    } finally { setSaving(false); }
  };

  return <div>
    <Typography.Title level={3}>IP 数据库配置</Typography.Title>
    <Typography.Paragraph type="secondary">为系统各页面的来源 IP 补充归属地信息。</Typography.Paragraph>
    <Card title="通研IP适配器" style={{ maxWidth: 800 }}>
      <Typography.Paragraph>来源：<Typography.Link href="https://ip.tongyaninfo.com/" target="_blank" rel="noopener noreferrer">ip.tongyaninfo.com</Typography.Link></Typography.Paragraph>
      <Alert type="info" showIcon title="解析默认关闭" description="开启后，公网来源 IP 由后台异步解析，页面稍后补齐归属地；解析超时或失败不影响事件采集和业务查询。内网、保留地址在本地识别，CIDR 显示为网段。" style={{ marginBottom: 24 }} />
      {loadFailed && <Alert type="error" showIcon title="无法读取配置，请检查管理员权限或稍后重试。" action={<Button size="small" onClick={() => setReload((value) => value + 1)}>重试</Button>} style={{ marginBottom: 16 }} />}
      {feedback && <Alert type={feedback.type} showIcon title={feedback.text} style={{ marginBottom: 16 }} />}
      <Spin spinning={loading}>
        <Form form={form} layout="vertical" initialValues={defaultIPLocationSettings} onFinish={save} disabled={loading || saving || loadFailed} style={{ maxWidth: 560 }}>
          <Form.Item name="enabled" label="启用 IP 解析" valuePropName="checked"><Switch checkedChildren="开启" unCheckedChildren="关闭" /></Form.Item>
          <Form.Item name="protocol" label="协议" rules={[{ required: true }]}>
            <Select options={[{ value: 'http', label: 'HTTP' }, { value: 'https', label: 'HTTPS' }]} onChange={(protocol) => form.setFieldValue('port', protocol === 'https' ? 443 : 80)} />
          </Form.Item>
          <Form.Item name="host" label="主机地址" extra="仅填写域名或 IP 地址，不包含协议、端口和路径。" rules={[
            { required: true, whitespace: true, message: '请输入主机地址' },
            { max: 253, message: '主机地址过长' },
            { validator: (_, value: string) => !value || (!/[\s/?#@]/.test(value.trim()) && !value.includes('://')) ? Promise.resolve() : Promise.reject(new Error('请仅填写域名或 IP 地址')) },
          ]}><Input placeholder="ip.tongyaninfo.com" /></Form.Item>
          <Space align="start" size="large" wrap>
            <Form.Item name="port" label="端口" rules={[{ required: true, message: '请输入端口' }, { type: 'integer', min: 1, max: 65535, message: '端口须为 1–65535 的整数' }]}><InputNumber min={1} max={65535} precision={0} style={{ width: 180 }} /></Form.Item>
            <Form.Item name="timeoutSeconds" label="解析超时时间（秒）" rules={[{ required: true, message: '请输入超时时间' }, { type: 'number', min: 0.1, max: 30, message: '超时范围为 0.1–30 秒' }]}><InputNumber min={0.1} max={30} step={0.1} style={{ width: 220 }} /></Form.Item>
          </Space>
          <Form.Item name="database" label="IP 数据库" rules={[{ required: true }]}><Select options={databases.map((database) => ({ value: database, label: database }))} /></Form.Item>
          <Form.Item><Button type="primary" htmlType="submit" loading={saving}>保存配置</Button></Form.Item>
        </Form>
      </Spin>
    </Card>
  </div>;
}
