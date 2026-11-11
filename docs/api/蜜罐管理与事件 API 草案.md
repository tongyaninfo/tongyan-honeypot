# 蜜罐管理与事件 API 草案

所有接口使用 `ApiResult<T>`，列表使用 `items / total / page / pageSize`，写操作记录管理员审计。以下接口是需求设计，不代表当前代码已经实现。

## 服务类型与适配器

```http
GET /api/v1/service-types
GET /api/v1/service-types/{adapterKey}
GET /api/v1/service-types/{adapterKey}/capabilities
```

返回协议、适配器版本、拟真等级、支持配置项、资源上限和兼容性矩阵。

## 服务人格与实例

```http
GET    /api/v1/service-profiles
POST   /api/v1/service-profiles
GET    /api/v1/service-profiles/{profileId}
PUT    /api/v1/service-profiles/{profileId}
POST   /api/v1/service-profiles/{profileId}/validate

GET    /api/v1/service-instances
POST   /api/v1/service-instances
GET    /api/v1/service-instances/{instanceId}
PUT    /api/v1/service-instances/{instanceId}
POST   /api/v1/service-instances/{instanceId}/validate
POST   /api/v1/service-instances/{instanceId}/apply
POST   /api/v1/service-instances/{instanceId}/start
POST   /api/v1/service-instances/{instanceId}/stop
POST   /api/v1/service-instances/{instanceId}/rollback
```

实例配置示例：

```json
{
  "instanceId": "ssh-default",
  "adapterKey": "ssh",
  "adapterVersion": "1",
  "profileId": "openssh-compatible",
  "bindings": [
    {
      "listenerId": "ssh-22",
      "bindAddress": "0.0.0.0",
      "port": 22,
      "transport": "tcp",
      "enabled": true
    },
    {
      "listenerId": "ssh-2222",
      "bindAddress": "0.0.0.0",
      "port": 2222,
      "transport": "tcp",
      "enabled": true
    }
  ],
  "resourcePolicy": {
    "maxConnections": 200,
    "maxConnectionsPerIp": 10,
    "handshakeTimeoutSeconds": 15,
    "idleTimeoutSeconds": 60,
    "maxFrameBytes": 65536
  }
}
```

应用接口必须支持 `dryRun=true`。校验内容包括适配器能力、人格字段、端口冲突、绑定权限、TLS 引用、资源上限和当前运行环境。

## 监听与运行状态

```http
GET /api/v1/listeners
GET /api/v1/listeners/{listenerId}
GET /api/v1/listeners/{listenerId}/metrics
GET /api/v1/listeners/{listenerId}/sessions
```

返回状态、配置版本、端口、活动连接数、accept 速率、错误数、队列状态和最近错误。

## 连接、事件与实时流

```http
GET /api/v1/connections
GET /api/v1/connections/{connectionId}
GET /api/v1/connections/{connectionId}/events
GET /api/v1/events
```

过滤条件：`sourceIp`、`destinationPort`、`adapterKey`、`instanceId`、`listenerId`、`eventType`、`status`、`fromUtc`、`toUtc`。

当前已提供：

```http
POST /hubs/honeypot/negotiate   # SignalR 协商，必须使用当前登录会话
```

SignalR 消息为 `eventAppended` 和 `runtimeChanged`。实时流只推送安全摘要和事件 ID，原始证据仍按查询权限读取；断线重连后前端重新拉取 REST 快照。

## 威胁清单

```http
GET  /api/v1/threats
GET  /api/v1/threats/{threatId}
GET  /api/v1/threats/by-ip/{sourceIp}
POST /api/v1/threats/{threatId}/status
POST /api/v1/threats/{threatId}/tags
GET  /api/v1/threats/{threatId}/timeline
```

威胁状态变更示例：

```json
{
  "status": "Muted",
  "reason": "内部扫描器维护窗口",
  "expiresAtUtc": "2026-11-09T02:00:00Z"
}
```

`Blocked` 在一期只表示策略状态和审计结果，不直接修改防火墙。真正的网络阻断需要独立接口、权限和回滚策略。

## 统一错误

- `VALIDATION_ERROR`：配置或请求字段不合法；
- `PORT_CONFLICT`：绑定地址、端口和传输层冲突；
- `ADAPTER_UNAVAILABLE`：适配器不存在或版本不兼容；
- `APPLY_FAILED`：应用配置失败且已回滚；
- `STORAGE_DEGRADED`：事件存储不可用或处于降级；
- `FORBIDDEN`：权限不足；
- `NOT_FOUND`：实例、连接、事件或威胁档案不存在。

错误响应仍保留真实 HTTP 状态码，不把所有失败返回为 200。

## 认证行为配置

ServiceProfile 默认包含：

```json
{
  "authMode": "AlwaysFail",
  "recordUsername": true,
  "recordPassword": true,
  "storeCredentialEvidence": true,
  "credentialEvidenceEncryptionKeyRef": "secret://honeypot/credential-evidence",
  "credentialEvidenceRetentionDays": 30,
  "maxAuthenticationAttempts": 3
}
```

`AlwaysFail` 是默认且推荐的唯一一期模式。接口返回的认证事件包含失败结果、协议失败码、材料类型和 `credentialArtifactId`；原始密码、私钥和完整认证票据只通过受控证据接口读取，不在普通列表中返回。

证据接口：

```http
GET    /api/v1/credential-evidence/{credentialArtifactId}
POST   /api/v1/credential-evidence/{credentialArtifactId}/export
DELETE /api/v1/credential-evidence/{credentialArtifactId}
```

单证据导出和删除保留在草案中。已实现的批量导出供管理员使用，会校验证据留存期限并记录导出审计，见[认证证据访问](README.md#认证证据访问)。
