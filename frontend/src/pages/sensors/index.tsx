import { Alert, Card, Empty, Spin, Table, Tag, Typography } from 'antd';
import type { ColumnsType } from 'antd/es/table';
import React, { useCallback, useEffect, useState } from 'react';
import { getListeners, normalizePage, type RuntimeListener } from '@/services/honeypot/api';

const ListenerPage: React.FC = () => {
  const [rows, setRows] = useState<RuntimeListener[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string>();

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const response = await getListeners();
      setRows(normalizePage(response.data).items);
      setError(undefined);
    } catch (loadError) {
      setError(loadError instanceof Error ? loadError.message : '监听器接口暂不可用');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const columns: ColumnsType<RuntimeListener> = [
    { title: '监听器', dataIndex: 'listenerId' },
    { title: '实例', dataIndex: 'serviceInstanceId' },
    { title: '适配器', dataIndex: 'adapterKey', render: (value) => <Tag color="blue">{value}</Tag> },
    { title: '绑定', render: (_, record) => `${record.bindAddress}:${record.port}/${record.transport}` },
    { title: '状态', dataIndex: 'state', render: (value) => <Tag color={value === 'Running' ? 'green' : 'default'}>{value || 'Unknown'}</Tag> },
    { title: '活动连接', dataIndex: 'activeConnections', render: (value) => value ?? 0 },
    { title: '已接受', dataIndex: 'acceptedCount', render: (value) => value ?? 0 },
    { title: '错误', dataIndex: 'errorCount', render: (value) => value ?? 0 },
  ];

  return (
    <div>
      <Typography.Title level={3}>监听器</Typography.Title>
      <Typography.Paragraph type="secondary">监听器由运行时统一管理，适配器只处理协议拟真和会话事件。</Typography.Paragraph>
      {error && <Alert message="监听器 API 暂不可用" description={error} type="warning" showIcon style={{ marginBottom: 16 }} />}
      <Card>
        {loading ? <Spin /> : rows.length === 0 ? <Empty description="尚未启动监听器" /> : <Table rowKey="listenerId" dataSource={rows} columns={columns} pagination={{ pageSize: 10 }} />}
      </Card>
    </div>
  );
};

export default ListenerPage;
