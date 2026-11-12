import { ApiOutlined, CaretRightOutlined, PauseOutlined } from '@ant-design/icons';
import { useAccess } from '@umijs/max';
import { Alert, Badge, Button, Card, Flex, Popconfirm, Spin, Tabs, Typography } from 'antd';
import { useEffect, useState } from 'react';
import { getMcpPermissions, getMcpSettings, type McpPermissions, type McpSettings, updateMcpSettings } from '@/services/honeypot/mcp';
import { reportApiError } from '@/utils/reportFormat';
import ApiKeyPanel from './ApiKeyPanel';
import AuditPanel from './AuditPanel';
import { mcpBaseUrl } from './display';
import './index.css';

export default function McpPage() {
  const access = useAccess();
  return access.canAdmin ? <McpContent /> : <Alert type="error" showIcon title="仅管理员可访问 MCP 服务。" />;
}

function McpContent() {
  const [settings, setSettings] = useState<McpSettings>();
  const [settingsLoading, setSettingsLoading] = useState(true);
  const [settingsFailed, setSettingsFailed] = useState(false);
  const [settingsSaving, setSettingsSaving] = useState(false);
  const [settingsReload, setSettingsReload] = useState(0);
  const [permissions, setPermissions] = useState<McpPermissions>();
  const [permissionsError, setPermissionsError] = useState(false);
  const [permissionsReload, setPermissionsReload] = useState(0);
  const [feedback, setFeedback] = useState<{ type: 'success' | 'error'; text: string }>();
  const origin = mcpBaseUrl();
  const reloadSettings = () => setSettingsReload((value) => value + 1);
  const auditDroppedCount = settings?.auditDroppedCount ?? 0;

  useEffect(() => {
    const controller = new AbortController();
    setSettingsLoading(true);
    setSettingsFailed(false);
    void getMcpSettings(controller.signal).then((response) => {
      if (controller.signal.aborted) return;
      if (!response.success || !response.data) throw response;
      setSettings(response.data);
    }).catch(() => {
      if (!controller.signal.aborted) setSettingsFailed(true);
    }).finally(() => {
      if (!controller.signal.aborted) setSettingsLoading(false);
    });
    return () => controller.abort();
  }, [settingsReload]);

  useEffect(() => {
    const controller = new AbortController();
    setPermissionsError(false);
    void getMcpPermissions(controller.signal).then((response) => {
      if (controller.signal.aborted) return;
      if (!response.success || !response.data) throw response;
      setPermissions(response.data);
    }).catch(() => {
      if (!controller.signal.aborted) setPermissionsError(true);
    });
    return () => controller.abort();
  }, [permissionsReload]);

  const saveSettings = async (data: Partial<Pick<McpSettings, 'enabled' | 'auditRetentionDays'>>, successText: string) => {
    if (!settings || settingsLoading || settingsFailed || settingsSaving) return false;
    setSettingsSaving(true);
    setFeedback(undefined);
    try {
      const response = await updateMcpSettings(data);
      if (!response.success || !response.data) throw response;
      setSettings(response.data);
      setFeedback({ type: 'success', text: successText });
      return true;
    } catch (error) {
      setFeedback({ type: 'error', text: reportApiError(error, '设置保存失败，请稍后重试。') });
      return false;
    } finally {
      setSettingsSaving(false);
    }
  };

  const stop = async () => { await saveSettings({ enabled: false }, 'MCP 服务已停止。'); };

  return (
    <Flex vertical gap={12} className="mcp-page">
      <Typography.Title level={3} style={{ marginBlock: '0 4px' }}>MCP 服务</Typography.Title>
      {settingsFailed && <Alert type="error" showIcon title="无法读取 MCP 服务设置" action={<Button size="small" onClick={reloadSettings}>重试</Button>} />}
      {settings?.auditAvailable === false && <Alert type="warning" showIcon title="MCP 审计存储异常" description="写入审计记录失败时，服务会拒绝新的写操作。" action={<Button size="small" loading={settingsLoading} disabled={settingsSaving} onClick={reloadSettings}>检查状态</Button>} />}
      {auditDroppedCount > 0 && <Alert type="warning" showIcon title={`本次进程运行期间，有 ${auditDroppedCount} 次调用因审计容量限制未保存。`} />}
      {feedback && <Alert type={feedback.type} showIcon closable title={feedback.text} onClose={() => setFeedback(undefined)} />}
      <Tabs items={[
        { key: 'service', label: 'MCP 服务', children: (
          <Flex vertical gap={16}>
            <Card size="small" styles={{ body: { padding: 16 } }}>
              <Flex justify="space-between" align="center" wrap="wrap" gap={14}>
                <Flex gap={12} align="flex-start">
                  <ApiOutlined aria-hidden style={{ fontSize: 24, color: 'var(--ant-color-primary, #1677ff)' }} />
                  <Flex vertical gap={5}>
                    <Flex align="center" gap={10} wrap="wrap">
                      <Typography.Text strong>服务状态</Typography.Text>
                      {settingsLoading ? <Spin size="small" /> : <Badge status={settingsFailed ? 'error' : settings?.enabled ? 'success' : 'default'} text={settingsFailed ? '读取失败' : settings?.enabled ? '运行中' : '已停止'} />}
                    </Flex>
                    <Typography.Text code className="mcp-service-endpoint">{origin}/mcp</Typography.Text>
                  </Flex>
                </Flex>
                {settings?.enabled ? (
                  <Popconfirm title="停止 MCP 服务？" description="新调用将被拒绝，已开始的调用会继续处理并记录结果。" onConfirm={stop} okText="停止" cancelText="取消" okButtonProps={{ danger: true }}>
                    <Button danger icon={<PauseOutlined />} loading={settingsSaving} disabled={settingsLoading || settingsFailed}>停止</Button>
                  </Popconfirm>
                ) : (
                  <Button type="primary" icon={<CaretRightOutlined />} loading={settingsSaving} disabled={settingsLoading || settingsFailed || !settings} onClick={() => { void saveSettings({ enabled: true }, 'MCP 服务已启动。'); }}>启动</Button>
                )}
              </Flex>
            </Card>
            <ApiKeyPanel origin={origin} permissions={permissions} permissionsError={permissionsError} reloadPermissions={() => setPermissionsReload((value) => value + 1)} />
          </Flex>
        ) },
        { key: 'audit', label: '调用记录', children: (
          <AuditPanel permissions={permissions} retentionDays={settingsFailed ? undefined : settings?.auditRetentionDays} settingsSaving={settingsSaving || settingsLoading} refreshSettings={() => !settingsSaving && reloadSettings()} onSaveRetention={(days) => saveSettings({ auditRetentionDays: days }, `审计留存已更新为 ${days} 天。`)} />
        ) },
      ]} />
    </Flex>
  );
}
