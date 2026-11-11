import {
  Alert,
  Button,
  Card,
  Col,
  Empty,
  InputNumber,
  Row,
  Space,
  Spin,
  Switch,
  Tabs,
  Tag,
  Typography,
  message,
} from 'antd';
import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  createServiceInstance,
  getListeners,
  getServiceInstances,
  getServiceTypes,
  normalizePage,
  startServiceInstance,
  stopServiceInstance,
  type ListenerBinding,
  type RuntimeListener,
  type ServiceInstance,
  type ServiceType,
} from '@/services/honeypot/api';
import { isServiceRunning, resolveServiceState } from './state';
import { connectHoneypotRealtime } from '@/services/realtime';

const defaultPorts: Record<string, number> = {
  // 兼容旧版 API；新服务默认值全部由后端提供，不覆盖已有实例。
  ssh: 22,
  mysql: 3306,
  mongodb: 27017,
  mssql: 1433,
  rdp: 3389,
};

const defaultFingerprints: Record<string, { hostName: string; product: string; version: string }> = {
  ssh: { hostName: 'ubuntu-web-01', product: 'OpenSSH', version: '9.6p1 Ubuntu-3ubuntu13.5' },
  mysql: { hostName: 'mysql-prod-01', product: 'MySQL Community Server', version: '8.0.36' },
  mongodb: { hostName: 'mongo-db-01', product: 'MongoDB', version: '7.0.5' },
  mssql: { hostName: 'WIN-SQL-01', product: 'Microsoft SQL Server', version: '15.0.4312.2' },
  rdp: { hostName: 'WIN-7F3A1C2', product: 'Microsoft Terminal Services', version: '10.0' },
};

const runtimeStateLabels: Record<string, string> = {
  Running: '运行中',
  Starting: '启动中',
  Stopped: '已停止',
  Failed: '失败',
};

const systemGroups = ['Windows', 'Linux'];
const systemGroupFor = (type: ServiceType) => type.systemGroup
  ?? ({ rdp: 'Windows', ssh: 'Linux' }[type.adapterKey]);
const categoryFor = (type: ServiceType) => type.category
  ?? (systemGroupFor(type) ? 'system' : databaseAdapterKeys.includes(type.adapterKey) ? 'database' : 'other');
const databaseAdapterKeys = ['mysql', 'mssql', 'mongodb'];

const newBinding = (instanceId: string, port: number, index = 0): ListenerBinding => ({
  listenerId: `${instanceId}-${port}-${index}`,
  bindAddress: '0.0.0.0',
  port,
  transport: 'tcp',
  enabled: true,
});

// 管理台不再让用户选择地址，统一由后端按全部 IPv4 地址监听，避免同一服务器出现重复配置。
const normalizeBindings = (bindings: ListenerBinding[]) =>
  bindings.map((binding) => ({ ...binding, bindAddress: binding.bindAddress || '0.0.0.0' }));

const isRequestError = (error: unknown) => {
  if (!error || typeof error !== 'object') {
    return false;
  }
  const candidate = error as { name?: string; response?: unknown };
  return candidate.name === 'BizError' || candidate.response !== undefined;
};

const ServicesPage: React.FC = () => {
  const [instances, setInstances] = useState<ServiceInstance[]>([]);
  const [serviceTypes, setServiceTypes] = useState<ServiceType[]>([]);
  const [listeners, setListeners] = useState<RuntimeListener[]>([]);
  const [draftBindings, setDraftBindings] = useState<Record<string, ListenerBinding[]>>({});
  const [persistedInstanceIds, setPersistedInstanceIds] = useState<Set<string>>(new Set());
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string>();
  const [workingId, setWorkingId] = useState<string>();

  const load = useCallback(async (savedDraft?: { instanceId: string; bindings: ListenerBinding[] }) => {
    setError(undefined);
    try {
      const [instancesResponse, typesResponse, listenersResponse] = await Promise.all([
        getServiceInstances(),
        getServiceTypes(),
        getListeners(),
      ]);
      const loadedInstances = normalizePage(instancesResponse.data).items;
      setInstances(loadedInstances);
      setPersistedInstanceIds(new Set(loadedInstances.map((instance) => instance.instanceId)));
      if (savedDraft) {
        setDraftBindings((current) => {
          // 只清掉刚保存的草稿，保留其他页签或保存期间产生的修改。
          if (current[savedDraft.instanceId] !== savedDraft.bindings) return current;
          const remaining = { ...current };
          delete remaining[savedDraft.instanceId];
          return remaining;
        });
      }
      setServiceTypes(normalizePage(typesResponse.data).items);
      setListeners(normalizePage(listenersResponse.data).items);
    } catch (loadError) {
      setError(loadError instanceof Error ? loadError.message : '服务实例接口暂不可用');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
    let cleanup: (() => Promise<void>) | undefined;
    void connectHoneypotRealtime({
      onRuntime: () => void load(),
      onEvent: () => void load(),
    })
      .then((dispose) => {
        cleanup = dispose;
      })
      .catch(() => {
        // 实时通道不可用时仍可通过 REST 刷新服务状态。
      });
    return () => {
      void cleanup?.();
    };
  }, [load]);

  const runtimeByListener = useMemo(
    () => new Map(listeners.map((listener) => [listener.listenerId, listener])),
    [listeners],
  );

  const runtimeByInstance = useMemo(() => {
    const result = new Map<string, RuntimeListener[]>();
    listeners.forEach((listener) => {
      const instanceId = listener.serviceInstanceId ?? listener.instanceId;
      if (!instanceId) {
        return;
      }
      const current = result.get(instanceId) ?? [];
      current.push(listener);
      result.set(instanceId, current);
    });
    return result;
  }, [listeners]);

  const getBindings = (instance: ServiceInstance) => draftBindings[instance.instanceId] ?? instance.bindings;

  const hasDraftChanges = (instance: ServiceInstance) =>
    JSON.stringify(normalizeBindings(getBindings(instance))) !== JSON.stringify(normalizeBindings(instance.bindings));

  const virtualInstances = useMemo(() => {
    const result = [...instances];
    serviceTypes.forEach((serviceType) => {
      if (result.some((instance) => instance.adapterKey === serviceType.adapterKey)) {
        return;
      }
      const port = serviceType.defaultPort ?? defaultPorts[serviceType.adapterKey] ?? 10000;
      const instanceId = `${serviceType.adapterKey}-default`;
      const fingerprint = defaultFingerprints[serviceType.adapterKey] ?? {
        hostName: 'HNY-SRV-01',
        product: serviceType.displayName,
        version: '1.0',
      };
      result.push({
        instanceId,
        displayName: serviceType.defaultInstanceName ?? serviceType.displayName,
        adapterKey: serviceType.adapterKey,
        profile: {
          profileId: `${instanceId}-profile`,
          adapterKey: serviceType.adapterKey,
          advertisedHostName: serviceType.defaultHostName ?? fingerprint.hostName,
          advertisedProduct: serviceType.defaultProduct ?? fingerprint.product,
          advertisedVersion: serviceType.defaultProductVersion ?? fingerprint.version,
          authMode: 'AlwaysFail',
          recordPassword: true,
          storeCredentialEvidence: true,
        },
        autoStart: false,
        bindings: [newBinding(instanceId, port)],
      });
    });
    return result;
  }, [instances, serviceTypes]);

  // 展示冲突而非悄悄改端口；后端仍进行实际端口占用校验。
  const conflictingPorts = (instance: ServiceInstance, bindings = getBindings(instance)) => {
    const occupied = new Set(instances.filter((item) => item.instanceId !== instance.instanceId)
      .flatMap((item) => [...item.bindings, ...getBindings(item)].filter((binding) => binding.enabled).map((binding) => binding.port)));
    const seen = new Set<number>();
    return bindings.filter((binding) => {
      if (!binding.enabled) return false;
      const conflict = occupied.has(binding.port) || seen.has(binding.port);
      seen.add(binding.port);
      return conflict;
    }).map((binding) => binding.port);
  };

  const updateDraftPort = (instance: ServiceInstance, binding: ListenerBinding, port: number | null) => {
    if (!port) {
      return;
    }
    const next = getBindings(instance).map((item) =>
      item.listenerId === binding.listenerId ? { ...item, port } : item,
    );
    setDraftBindings((current) => ({ ...current, [instance.instanceId]: next }));
  };

  const addPort = (instance: ServiceInstance) => {
    const bindings = getBindings(instance);
    const usedPorts = new Set(bindings.map((binding) => binding.port));
    let port = Math.max(...bindings.map((binding) => binding.port), serviceTypes.find((type) => type.adapterKey === instance.adapterKey)?.defaultPort ?? defaultPorts[instance.adapterKey] ?? 10000) + 1;
    while (usedPorts.has(port)) {
      port += 1;
    }
    setDraftBindings((current) => ({
      ...current,
      [instance.instanceId]: [...bindings, newBinding(instance.instanceId, port, bindings.length)],
    }));
  };

  const removePort = (instance: ServiceInstance, listenerId: string) => {
    const bindings = getBindings(instance);
    if (bindings.length <= 1) {
      message.warning('至少保留一个监听端口');
      return;
    }
    setDraftBindings((current) => ({
      ...current,
      [instance.instanceId]: bindings.filter((binding) => binding.listenerId !== listenerId),
    }));
  };

  const applyPorts = async (instance: ServiceInstance) => {
    if (!hasDraftChanges(instance)) {
      message.info('端口配置没有变化');
      return;
    }
    if (conflictingPorts(instance).length) {
      message.warning('监听端口与其他实例或本实例重复，请调整后再应用');
      return;
    }
    const draft = getBindings(instance);
    const bindings = normalizeBindings(draft);
    const runtime = runtimeByInstance.get(instance.instanceId) ?? [];
    const isRunning = runtime.some((item) => item.state === 'Running' || item.state === 'Starting');
    setWorkingId(instance.instanceId);
    let saved = false;
    try {
      await createServiceInstance({ ...instance, bindings });
      saved = true;
      setPersistedInstanceIds((current) => new Set(current).add(instance.instanceId));
      if (isRunning) {
        await startServiceInstance(instance.instanceId);
        message.success('端口配置已应用，监听器已重新加载');
      } else {
        message.success('端口配置已保存');
      }
    } catch (applyError) {
      if (!isRequestError(applyError)) {
        message.error(applyError instanceof Error ? applyError.message : '应用端口配置失败');
      }
    } finally {
      if (saved) await load({ instanceId: instance.instanceId, bindings: draft });
      setWorkingId(undefined);
    }
  };

  const toggleInstance = async (instance: ServiceInstance) => {
    if (hasDraftChanges(instance)) {
      message.warning('请先点击“应用端口”保存修改，再启动或停止实例');
      return;
    }
    const runtime = runtimeByInstance.get(instance.instanceId) ?? [];
    const isRunning = runtime.some((item) => item.state === 'Running' || item.state === 'Starting');
    if (!isRunning && conflictingPorts(instance).length) {
      message.warning('监听端口与其他实例或本实例重复，请调整后再启动');
      return;
    }
    setWorkingId(instance.instanceId);
    try {
      if (!persistedInstanceIds.has(instance.instanceId)) {
        await createServiceInstance({ ...instance, bindings: normalizeBindings(instance.bindings) });
        setPersistedInstanceIds((current) => new Set(current).add(instance.instanceId));
      }
      if (isRunning) {
        await stopServiceInstance(instance.instanceId);
        message.success('实例已停止');
      } else {
        await startServiceInstance(instance.instanceId);
        message.success('实例已启动');
      }
      await load();
    } catch (toggleError) {
      if (!isRequestError(toggleError)) {
        message.error(toggleError instanceof Error ? toggleError.message : isRunning ? '停止失败' : '启动失败');
      }
    } finally {
      setWorkingId(undefined);
    }
  };

  const toggleAutoStart = async (instance: ServiceInstance, checked: boolean) => {
    if (checked && conflictingPorts(instance).length) {
      message.warning('监听端口冲突，请调整后再开启自动启动');
      return;
    }
    if (hasDraftChanges(instance)) {
      message.warning('请先点击“应用端口”保存修改，再调整重启自动启动策略');
      return;
    }

    setWorkingId(instance.instanceId);
    try {
      await createServiceInstance({
        ...instance,
        autoStart: checked,
        bindings: normalizeBindings(instance.bindings),
      });
      message.success(checked ? '已开启重启自动启动' : '已关闭重启自动启动');
      await load();
    } catch (toggleError) {
      if (!isRequestError(toggleError)) {
        message.error(toggleError instanceof Error ? toggleError.message : '保存重启策略失败');
      }
    } finally {
      setWorkingId(undefined);
    }
  };

  const renderInstance = (instance: ServiceInstance) => {
    const runtime = runtimeByInstance.get(instance.instanceId) ?? [];
    const runtimeStates = runtime
      .map((item) => item.state)
      .filter((item): item is string => item !== undefined);
    const isRunning = isServiceRunning(instance.currentState, runtimeStates);
    const state = resolveServiceState(instance.currentState, runtimeStates);
    const bindings = getBindings(instance);
    const conflicts = conflictingPorts(instance);
    const hostName = instance.profile.advertisedHostName
      ?? defaultFingerprints[instance.adapterKey]?.hostName
      ?? 'HNY-SRV-01';

    return (
      <Card
        size="small"
        key={instance.instanceId}
        title={
          <Space wrap>
            <Typography.Text strong>{instance.displayName || instance.instanceId}</Typography.Text>
            <Tag>{instance.instanceId}</Tag>
            <Tag color={state === 'Running' ? 'green' : state === 'Failed' ? 'red' : 'default'}>
              {runtimeStateLabels[state] ?? state}
            </Tag>
            <Tag color="geekblue">{hostName}</Tag>
          </Space>
        }
        extra={
          <Button
            size="small"
            type={isRunning ? 'default' : 'primary'}
            danger={isRunning}
            loading={workingId === instance.instanceId}
            onClick={() => void toggleInstance(instance)}
          >
            {isRunning ? '停止' : '启动'}
          </Button>
        }
        style={{ marginBottom: 12 }}
      >
        <Space direction="vertical" style={{ width: '100%' }} size="small">
          <Typography.Text type="secondary">本服务器监听全部 IPv4 地址（0.0.0.0），一个实例支持多个端口。</Typography.Text>
          {conflicts.length > 0 && <Alert type="warning" showIcon message={`端口冲突：${[...new Set(conflicts)].join('、')}。请调整端口后再启动。`} />}
          {bindings.map((binding) => {
            const listener = runtimeByListener.get(binding.listenerId);
            return (
              <Space key={binding.listenerId} wrap style={{ width: '100%' }}>
                <InputNumber
                  min={1}
                  max={65535}
                  value={binding.port}
                  onChange={(port) => updateDraftPort(instance, binding, port)}
                />
                <Tag>全部地址</Tag>
                <Tag color={listener?.state === 'Running' ? 'green' : 'default'}>
                  {listener?.state ? runtimeStateLabels[listener.state] ?? listener.state : '未启动'}
                </Tag>
                <Typography.Text type="secondary">
                  连接 {listener?.activeConnections ?? 0} / 已接收 {listener?.acceptedCount ?? 0}
                </Typography.Text>
                <Button size="small" onClick={() => removePort(instance, binding.listenerId)}>
                  删除端口
                </Button>
              </Space>
            );
          })}
          <Space wrap>
            <Typography.Text type="secondary">重启自动启动</Typography.Text>
            <Switch
              size="small"
              checked={instance.autoStart === true}
              disabled={workingId === instance.instanceId || hasDraftChanges(instance)}
              loading={workingId === instance.instanceId}
              onChange={(checked) => void toggleAutoStart(instance, checked)}
            />
            <Typography.Text type="secondary">
              {instance.autoStart === true ? '服务重启后自动恢复监听' : '服务重启后保持停止'}
            </Typography.Text>
          </Space>
          {instance.lastError && state === 'Failed' && (
            <Typography.Text type="danger">启动失败：{instance.lastError}</Typography.Text>
          )}
          <Space>
            <Button type="dashed" size="small" onClick={() => addPort(instance)}>
              新增监听端口
            </Button>
            <Button
              type="primary"
              size="small"
              ghost
              disabled={!hasDraftChanges(instance)}
              loading={workingId === instance.instanceId}
              onClick={() => void applyPorts(instance)}
            >
              应用端口
            </Button>
            {hasDraftChanges(instance) && <Typography.Text type="warning">有未应用的端口修改</Typography.Text>}
          </Space>
        </Space>
      </Card>
    );
  };

  const renderAdapterCard = (serviceType: ServiceType) => {
    const instance = virtualInstances.find((item) => item.adapterKey === serviceType.adapterKey);
    return (
      <Card
        key={serviceType.adapterKey}
        data-testid={`service-card-${serviceType.adapterKey}`}
        title={
          <Space wrap>
            <Typography.Text strong>{serviceType.displayName}</Typography.Text>
            <Tag color="blue">{serviceType.adapterKey}</Tag>
          </Space>
        }
        extra={<Tag color="blue">单实例</Tag>}
      >
        {instance ? renderInstance(instance) : <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="尚未配置服务" />}
      </Card>
    );
  };

  const renderAdapterGrid = (types: ServiceType[]) => (
    <Row gutter={[16, 16]}>
      {types.map((serviceType) => (
        <Col xs={24} xl={12} key={serviceType.adapterKey}>{renderAdapterCard(serviceType)}</Col>
      ))}
    </Row>
  );

  const databaseTypes = serviceTypes.filter((type) => categoryFor(type) === 'database');
  const otherTypes = serviceTypes.filter((type) => categoryFor(type) !== 'database' && !systemGroups.includes(systemGroupFor(type) ?? ''));
  const emptyAdapters = <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无可用适配器" />;

  return (
    <div>
      <Space direction="vertical" size="large" style={{ display: 'flex' }}>
        <div>
          <Typography.Title level={3} style={{ marginBottom: 4 }}>
            服务实例与监听器
          </Typography.Title>
          <Typography.Text type="secondary">
            一个服务器对应每种适配器一个服务实例；端口修改后点击“应用端口”，启动和停止按钮会根据当前状态切换。
          </Typography.Text>
        </div>
        {error && <Alert message="服务接口暂不可用" description={error} type="warning" showIcon />}
        {loading ? (
          <Spin />
        ) : serviceTypes.length === 0 ? (
          <Empty description="暂无可用适配器" />
        ) : (
          <Tabs
            defaultActiveKey="system"
            items={[
              {
                key: 'system',
                label: '系统',
                children: (
                  <Row gutter={[16, 16]}>
                    {systemGroups.map((label) => {
                      const types = serviceTypes.filter((type) => systemGroupFor(type) === label);
                      return (
                        <Col xs={24} xl={12} key={label}>
                          <Typography.Title level={4} style={{ marginTop: 0 }}>{label}</Typography.Title>
                          {types.length ? <Space direction="vertical" size="middle" style={{ display: 'flex' }}>{types.map(renderAdapterCard)}</Space> : emptyAdapters}
                        </Col>
                      );
                    })}
                    {otherTypes.length > 0 && (
                      <Col span={24}>
                        <Typography.Title level={4} style={{ marginTop: 0 }}>其他</Typography.Title>
                        {renderAdapterGrid(otherTypes)}
                      </Col>
                    )}
                  </Row>
                ),
              },
              {
                key: 'database',
                label: '数据库',
                children: databaseTypes.length ? renderAdapterGrid(databaseTypes) : emptyAdapters,
              },
            ]}
          />
        )}
      </Space>
    </div>
  );
};

export default ServicesPage;
