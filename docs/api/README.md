# API 约定

所有业务接口返回 `ApiResult<T>`：

```json
{
  "success": true,
  "code": "OK",
  "message": "success",
  "data": {}
}
```

列表接口统一返回：

```json
{
  "items": [],
  "total": 0,
  "page": 1,
  "pageSize": 20
}
```

## 当前已实现接口

- `GET /health`：服务健康状态。
- `GET /`：初始化状态说明。
- `POST /api/v1/events/preview`：使用受控观测字段运行一次判定预览。
- `GET /api/v1/service-types`：内置适配器能力。
- `GET/POST /api/v1/service-instances`：服务实例查询和 SQLite 配置保存；实例、监听端口和启停策略随应用重启保留。
- `POST /api/v1/service-instances/{id}/start`：启动实例监听。
- `POST /api/v1/service-instances/{id}/stop`：停止实例全部监听。
- `GET /api/v1/listeners`：监听器运行状态。
- `GET /api/v1/metrics/overview`：运行总览聚合指标、适配器分布、结果分布、24 小时趋势和监听器明细。
- `GET /api/v1/events` 查询事件，可通过 `view=activity` 获取威胁事件页所用的行为列表。`GET /api/v1/connections/{connectionId}/events` 查询该连接的原始事件步骤。
- `GET /api/v1/threats`、`GET /api/v1/threats/by-ip/{ip}`：威胁清单查询。
- `GET /api/v1/credential-evidence` 查询认证证据摘要。`GET /api/v1/credential-evidence/{credentialArtifactId}` 和 `GET /api/v1/credential-evidence/audit` 分别供管理员读取单份证据原文和访问审计。
- `POST /api/v1/credential-evidence/export`：供管理员批量读取证据原文，管理台据此生成详细 Excel。
- `POST /hubs/honeypot/negotiate`：SignalR 实时通道协商，必须携带当前登录 Bearer 会话；WebSocket 连接使用同一 token 的 `access_token`。
- 报告统计、通知设置、邮件任务和报告历史接口见下文“报告邮件通知”。

## 威胁事件查询

`GET /api/v1/events` 接受 `sourceIp`、`adapterKey`、`destinationPort` 和 `eventType` 筛选。省略 `view` 或传入 `view=raw` 时返回原始事件。未识别的 `view` 值返回 HTTP 400 和 `INVALID_VIEW`。

`view=activity` 按 `connectionId` 关联步骤。一条连接内的每次认证尝试分别返回一行。没有进入认证的连接返回一行，优先展示存储降级或协议异常等诊断，否则展示连接建立。来源相同或时间接近的不同连接分别保留。`eventType` 在投影后按代表事件筛选。

活动条目的 `eventId` 指向代表事件，`eventCount` 表示该连接的事件步骤数量。客户端可使用 `connectionId` 查看完整步骤，用 `credentialArtifactId` 关联认证证据。两个视图的 `total` 均按所选视图和筛选条件统计，原始事件、威胁计数及证据存储独立于列表视图。

## 认证证据访问

证据摘要接口对已登录用户开放，仅返回来源、协议、材料类型、关联 ID、采集和留存时间等元数据。证据原文接口根据当前 Bearer 会话在服务端验证 `Administrator` 角色（兼容旧 `admin`，忽略大小写），返回 `data.summary` 和 `data.content`，并设置 `Cache-Control: no-store`。前端使用同一服务端角色合同；页面显示不能替代服务端权限检查。

应用已初始化时，无有效会话返回 HTTP 401，非管理员请求原文或审计返回 HTTP 403，管理员请求不存在或已过期的证据返回 HTTP 404 和 `NOT_FOUND_OR_EXPIRED`。原文读取结果写入有界内存审计，审计接口返回访问人、时间、证据 ID 和结果等元数据。RDP NTLM 证据保存收到的挑战和响应，材料类型为 `Response`。

原文导出请求形如 `{ "artifactIds": ["cred-00000000000000000000000000000001"] }`。每批最多 8 个不同的证据 ID，请求正文最多 4 KiB。只有管理员可调用；不合法的批次返回 HTTP 400。成功时 `data.items` 按请求顺序返回 `artifactId`、`outcome`，状态为 `OK` 的项目包含 `evidence.summary` 和 `evidence.content`。已过期或不存在的项目标记为 `NOT_FOUND_OR_EXPIRED`，不返回原文。响应设置 `Cache-Control: no-store`，审计用 `operation` 区分 `Read` 和 `Export`，不保存材料原文。

## 规划接口

服务类型、服务人格、服务实例、监听器、连接、事件和威胁清单接口见[蜜罐管理与事件 API 草案](蜜罐管理与事件 API 草案.md)。

连接建立后先记录 `ConnectionAccepted`，再进入协议握手；事件查询必须保留 `listenerId`、`serviceInstanceId` 和目标端口，不能只按协议名称聚合。

管理台按单服务器、单适配器实例展示服务卡片；实例默认监听 `0.0.0.0`，端口可以配置多个。端口输入仅修改页面草稿，点击“应用端口”后才写入服务端；启动/停止共用一个按运行状态切换的按钮。

真实传感器上报、完整事件/证据生产持久化、细粒度 RBAC、登录/封禁/解封事件告警、可靠审计和自动阻断接口尚未建立。报告通知及报告事件白名单已实现 SQLite 持久化；原事件列表、威胁档案和认证证据仍是进程内实现，不能把报告持久化等同于完整证据仓库。

## 用户体系接口

- `GET /api/v1/setup/status`：查询是否完成首次初始化。
- `POST /api/v1/setup/initialize`：在无用户时创建首个管理员。
- `POST /api/v1/auth/login`：登录并获取 Bearer Token。
- `GET /api/v1/auth/me`：查询当前会话用户。
- `POST /api/v1/auth/logout`：注销当前会话。
- `GET /api/v1/users`：登录后查询用户摘要。

系统不预置管理员。首次部署必须先访问 `/setup` 完成初始化，之后管理 API 才会接受登录会话。

## IP 数据库配置与异步归属地

- `GET /api/v1/settings/ip-location`：管理员读取通研 IP 适配器设置。
- `PUT /api/v1/settings/ip-location`：管理员保存设置，立即使旧解析任务与缓存失效。
- `POST /api/v1/ip-locations/resolve`：已登录用户提交最多 100 个 IP 或 CIDR，查询缓存并尝试入队；请求不等待上游解析。

配置字段和默认值：

```json
{
  "enabled": false,
  "protocol": "https",
  "host": "ip.tongyaninfo.com",
  "port": 443,
  "database": "CZ88",
  "timeoutSeconds": 2
}
```

`protocol` 仅支持 `http/https`；`host` 仅接受主机名或 IP，不接受完整 URL、路径或凭据；`port` 范围为 1–65535；`timeoutSeconds` 范围为 0.1–30。`database` 单选 `CZ88 / ip2location / ip2region / dbip / ipinfo / geolite2`。

批量请求示例：

```json
{ "ips": ["192.0.2.10", "192.0.2.0/24"] }
```

成功时 `data` 包含 `enabled` 与 `items`；每项包含 `ip / status / displayName / country / province / city / district / isp`。`status` 为 `disabled / pending / resolved / private / reserved / network / failed / invalid / busy`。私网、保留地址和网段由本机识别，不发往供应方；公网缓存缺失时返回 `pending`，页面稍后合批查询补齐。缺失的位置字段返回空字符串，不推测区县。上游超时或队列已满只影响该 IP 的显示状态。

界面展示与来源、性能边界和回滚方式见 [IP 归属地异步解析方案](../spec/IP归属地异步解析方案.md)。

## 报告邮件通知

本次仅实现运行报告邮件，不含登录、封禁或解封事件通知。以下接口使用当前 Bearer 会话、统一 `ApiResult<T>` 和 `Cache-Control: no-store`；除即时报告查询允许已登录用户外，其余均在服务端要求管理员角色。

| 方法与路径 | 权限 | 内容 |
| --- | --- | --- |
| `GET /api/v1/settings/notifications` | 管理员 | 读取 SMTP、频率与三类订阅；仅返回 `hasCredential`，不返回授权码或密文。 |
| `PUT /api/v1/settings/notifications` | 管理员 | 正文为 `{ "settings": { ... }, "authorizationCode": "..." }`；授权码为只写字段，省略、`null` 或空字符串表示保留原值。 |
| `POST /api/v1/notifications/test` | 管理员 | 正文 `{ "recipient": "operator@example.invalid" }`，使用已保存配置创建测试任务；通知总开关关闭时仍允许显式测试。 |
| `GET /api/v1/notifications/emails` | 管理员 | 支持 `page/pageSize/kind/status/recipient/fromUtc/toUtc`；时间按创建时间筛选，结束时间不包含。 |
| `GET /api/v1/notifications/emails/{id}` | 管理员 | 返回正文快照、模板版本、尝试记录和 `canRetry`。 |
| `POST /api/v1/notifications/emails/{id}/retry` | 管理员 | 仅允许失败或结果不确定的邮件重试，仍检查冷却与配额。 |
| `GET /api/v1/reports` | 已登录用户 | `period=day/week/month/custom`；默认 `day`。 |
| `POST /api/v1/reports/send` | 管理员 | 正文支持 `period/startAtUtc/endAtUtc/recipients`；创建报告快照及各收件人的独立发送任务。 |
| `GET /api/v1/reports/history` | 管理员 | 支持 `page/pageSize/kind`，查询已生成报告快照。 |
| `GET /api/v1/reports/history/{id}` | 管理员 | 读取生成时冻结的 `OperationReport`，不会重新计算历史数据。 |

发送、测试、重试返回 **HTTP 202** 和 `data.deliveryIds`，表示已经排队。分页结果为 `items/total/page/pageSize`，每页最多 100 条；写请求正文上限 32 KiB。参数错误返回 400，未登录/无权限返回 401/403，不存在返回 404，冲突返回 409，超过冷却或配额的入队请求返回 429，存储或凭据不可用返回 503。发件 Worker 遇到小时配额时保留任务并延期，不将它误标为 SMTP 失败。

SMTP 默认值：通知关闭、端口 `465`、`useSsl=true`、`securityMode=SslOnConnect`、超时 15 秒。勾选 SSL/TLS 时支持隐式 TLS 和强制 `StartTls`；强制 STARTTLS 失败不会自动降级明文。三类订阅默认关闭、默认北京时间 `08:00`；周报固定周一、月报固定每月一日。默认小时尝试配额为全局 100 次、单收件人 20 次，测试和手动重试冷却各 60 秒。

报告日期必须包含 `Z` 或显式时区偏移。自然日/周/月从北京时间周期起点统计至当前时刻；`custom` 必须同时提供 `startAtUtc/endAtUtc`，采用 `[start,end)`，不得超过当前时间，最长 366 天。例如：

```text
GET /api/v1/reports?period=custom&startAtUtc=2026-11-08T16:00:00Z&endAtUtc=2026-11-09T16:00:00Z
```

报告包含 `period/coverage/totals/comparison/trend/protocols/ports/sources/usernames/authenticationMethods/riskSignals/evidence/regions/runtime/mailSummary/notes`。无可用观测时计数为 `null`；有部分覆盖时计数仅代表已记录数据。趋势逐桶返回 `coverageStatus`，未采集且无事件的桶为 `null`，不得在客户端补零。只有两期时长相同、覆盖完整且上期基数大于零时才给变化率；短月不足时保留实际计数并说明不可比。

邮件状态为 `Pending/Sending/Accepted/Retrying/Failed/Unknown`。`Accepted` 仅表示 SMTP 已受理；`Unknown` 表示提交或结果落库阶段不确定，停止自动重试，人工重试可能重复投递。报告中的邮件健康统计指本区间内创建的任务在报告生成时的状态，不是已到达或已读统计。

六表迁移、模板位置、凭据保护、验证命令与未部署边界见[报告邮件通知实施方案](../spec/报告邮件通知实施方案.md)。
