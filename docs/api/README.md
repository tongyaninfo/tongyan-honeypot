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
- `POST /api/v1/service-instances/{id}/restart-policy` 接收 `{ "autoStart": true }` 或关闭值，保存重启恢复策略并返回服务实例。实例的期望运行状态由启停操作维护。
- `GET /api/v1/listeners`：监听器运行状态。
- `GET /api/v1/metrics/overview` 返回首页指标、协议活动、小时趋势、监听器明细及统计时点 `generatedAtUtc`。`GET /api/v1/metrics/summary` 返回最近 24 小时的接纳连接、认证尝试、协议异常及当前威胁档案、监听器、存储状态。
- `GET /api/v1/metrics/overview/connections` 根据卡片或协议指标分页查询连接，支持 `scope/page/pageSize/asOfUtc`。
- `GET /api/v1/metrics/overview/connection-map` 返回已接纳连接的地图快照，默认最近 10 分钟，可用 `windowSeconds` 切换。
- `GET /api/v1/events?view=activity` 供首页最近活动和威胁事件页使用。按连接追溯时，`GET /api/v1/connections/{connectionId}/summary` 返回连接摘要，`GET /api/v1/connections/{connectionId}/events` 返回仍在留存期内的完整脱敏步骤。
- `GET /api/v1/threats`、`GET /api/v1/threats/by-ip/{ip}`：威胁清单查询。
- `GET /api/v1/credential-evidence` 查询认证证据摘要。`GET /api/v1/credential-evidence/{credentialArtifactId}` 和 `GET /api/v1/credential-evidence/audit` 分别供管理员读取单份证据原文和访问审计。
- `GET /api/v1/password-book`：管理员按 `keyword/page/pageSize` 查询密码组合、认证次数及最近使用时间。
- `GET /api/v1/management/audits` 供管理员按 `page/pageSize` 查询关键管理操作的时间、操作者、对象、动作与 HTTP 状态。预先登记的操作在中断后未写回结果时，查询会将其标记为 `Unknown`。
- `POST /api/v1/credential-evidence/export`：供管理员批量读取证据原文，管理台据此生成详细 Excel。
- `POST /hubs/honeypot/negotiate`：SignalR 实时通道协商，必须携带当前登录 Bearer 会话；WebSocket 连接使用同一 token 的 `access_token`。
- 报告统计、通知设置、邮件任务和报告历史接口见下文“报告邮件通知”。
- MCP 管理接口及智能体接入见下文“MCP 服务”。

## 运行总览连接明细

客户端将首页返回的 `generatedAtUtc` 原样作为 `asOfUtc` 传给下钻，翻页时沿用该值。省略时使用当前时间。SQLite 对持久化指标按事件时间截止和当前留存范围筛选。

| `scope` | 首页字段 | 明细口径 |
| --- | --- | --- |
| `active` | `activeConnections` | 由监听器直接观测。带 `asOfUtc` 取首页采样时的活动连接，同一页组内后来新建或关闭的连接不改变结果。省略时查询当前活动连接。 |
| `accepted` | `acceptedConnections` | 截止时点向前滚动 24 小时，每个有实际接纳记录的连接一行。准入拒绝另有连接摘要。 |
| `authenticationFailures` | `todayAuthenticationFailures` | 从北京时间当日零时到截止时点，每条结果为 `failure`、`rejected` 或 `invalid` 的 `AuthenticationAttempted` 一行。一个连接的多次认证分别计数。 |
| `threatConnections` | `traceableThreatIpCount` | 有效威胁档案中有可追溯连接的来源各一行，展示其最近连接。仅观察到准入拒绝的来源也可下钻。`threatIpCount` 包含所有有效档案，两者的差值是缺少可回看连接的档案数。 |

活动连接快照在当前 API 进程内保留 5 分钟，同一秒内的首页请求可共用一次采样。携带过期、进程重启前或无法识别的时点查询 `scope=active` 会返回 HTTP 410 和 `OVERVIEW_SNAPSHOT_EXPIRED`。客户端应刷新首页，用新返回的时点重新打开下钻。

`scope=adapterActivity` 使用 `adapterKey` 筛选协议，`metric` 指定 `acceptedConnections`、`authenticationFailures`、`sourceIpCount` 或 `protocolViolations`。窗口从 23 小时前的整点起，到统计时点为止。来源 IP 在接纳连接、认证失败和协议异常的合集中按地址去重，每个地址展示最近一条匹配活动。

`activityByHour` 的 UTC 小时键覆盖当前及此前 23 个小时，统计报表事实中的接纳连接和认证失败。`coverageStatus` 为 `complete`、`partial` 或 `unknown`。无采集覆盖也无事件的小时计数为 `null`，部分覆盖只显示已记录数量。若旧版库有仅存报表的事实，小时趋势仍包含这些记录，`reportOnlyEvents` 给出过去 24 小时的此类事件数。可下钻卡片和协议活动只纳入可以定位到连接或事件的记录。

连接明细按时间倒序、同一时间按 `id` 升序分页，返回 `items/total/page/pageSize`。每行含 `id/connectionId/occurredAtUtc/sourceIp/sourcePort/adapterKey/destinationPort`。认证失败可带 `username/credentialArtifactId/materialType`，协议异常可带诊断摘要。未知或缺少 `scope` 返回 HTTP 400 和 `INVALID_SCOPE`。查看已采集的认证原文须使用单条证据接口，并接受服务端权限检查和读取审计。

首页和指标摘要都返回 `eventStorage`。`lockRetries` 记录锁冲突后的应用重试，`rejectedEvents` 记录最终未持久化的事件。`writeFailuresByCode` 按错误码累计，`faultsByStage` 可区分失败位置、最近失败和后续恢复。数据库占用和文件系统可用空间分别见 `databaseBytes` 和 `freeDiskBytes`，`diskSpaceStatus` 表示余量状态。兼容字段 `diskBudgetBlocked` 表示观测到实际的 SQLite 存储空间耗尽，证据和事件写入已取消预设容量配额。

## 运行总览连接地图

`GET /api/v1/metrics/overview/connection-map` 需要当前登录会话，设置 `Cache-Control: no-store`。`windowSeconds` 支持 `60`、`600`、`7200`、`86400`，默认 `600`，其他值返回 HTTP 400 和 `INVALID_WINDOW`。SQLite 从连接摘要中读取接纳时刻落在窗口内的全部连接，含起点和终点，每个连接计一次。后续握手、认证、关闭和准入拒绝不会增加地图计数。

| 字段 | 说明 |
| --- | --- |
| `sampledAtUtc / windowSeconds / locationEnabled` | UTC 采样时刻、当前窗口秒数及 IP 定位开关。 |
| `target` | `status` 为 `ready/pending/unavailable/disabled`，可带 `label/latitude/longitude/source/updatedAtUtc`。同一目标的缓存到期，或切换定位设置后仍在沿用上次成功结果时，`stale=true`。 |
| `origins` | 窗口内已定位连接的来源汇总。每项含 `id/longitude/latitude/locationLabel/adapterKey/connectionCount/sourceIpCount/sources`。`sources` 每项含 `ip/country`，最多返回 12 个公网 IP，`sourceIpCount` 是该地点或格网的去重 IP 总数。多地点合并后采用最近连接的坐标和服务类型。 |
| `adapterKeys` | 所有已定位连接涉及的服务类型，用于图例。 |
| `events` | 最近 100 条具有有效坐标的连接，供实时飞线匹配和旧客户端使用。每条含 `id/occurredAtUtc/adapterKey/latitude/longitude/locationLabel/sourceIp/country`，`sourceIp` 为规范化公网 IP，`country` 缺失时为空。`locationSource/locationVersion` 随定位结果提供。 |
| `coverage` | `observed` 为时间窗和快照内去重连接总数，等于 `mapped + unknown + private + pending`。`mapped` 为有坐标，`unknown` 为缺坐标、定位未启用或不可定位，`private` 为私网及其他特殊用途地址。`pending` 包含等待解析和等待入队，`deferred` 为其中尚在等待入队的连接。`omitted` 等于 `mapped - events.length`，用于兼容旧版；超出飞线列表的已定位连接仍汇总到 `origins`。 |

首次打开查询窗口快照，页面经 `eventAppended` 接到接纳事件后合并刷新。每次检查所有候选 IP 的缓存，新 IP 最多 128 个按现有队列容量逐步入队。悬停来源点使用响应中的来源汇总。100 条飞线仅限制动画，窗口统计与地点汇总覆盖全部符合条件的连接。详见 [实时飞线地图实施方案](../spec/实时飞线地图实施方案.md)。

## 威胁事件查询

`GET /api/v1/events` 接受 `sourceIp`、`adapterKey`、`destinationPort`、`eventType` 和 `connectionIds` 筛选。`connectionIds` 为逗号分隔的连接 ID，最多 100 个。省略 `view` 或传入 `view=raw` 时逐条返回仍可回看的脱敏事件。未识别的 `view` 值返回 HTTP 400 和 `INVALID_VIEW`。

`view=activity` 按 `connectionId` 关联步骤，每次 `AuthenticationAttempted` 或 `AuthorizationDenied` 各返回一行。单纯访问拒绝保留在活动列表中，认证次数只统计实际认证尝试。没有上述事件的连接返回一条代表事件，优先展示存储降级、协议异常等诊断，其次展示接纳或准入拒绝。`eventType` 在选出代表事件后筛选。首页只取所请求页的展示字段。

活动条目的 `eventId` 指向实际事件。常规活动列表中的 `eventCount` 表示该连接累计观测步数，`connectionCloseObserved` 表示是否记录了关闭。显式按 `connectionIds` 筛选时，`eventCount` 统计筛选范围内仍可回看的步骤。两个视图的 `total` 均按当前视图和筛选条件统计。

常规活动列表只计仍可回看的认证或代表事件。若代表事件已到期、该连接的关闭记录仍在留存期内，仍可按连接 ID 查看摘要和剩余步骤。

`GET /api/v1/connections/{connectionId}/summary` 返回连接两端、监听器、服务实例、`admissionOutcome/admissionReason/admittedAtUtc`、最后一次协议阶段和 `closedAtUtc/closeReason`。`observedCount` 是已持久化的累计步骤数，`availableCount` 是当前可回看明细数，客户端可用同一连接的 `/events` 按序读取每条明细。未观测到关闭时，关闭时刻和原因均为空，重启时也不会推断断开。只存旧报表的记录无法恢复连接。摘要缺失或已过期时返回 HTTP 404 和 `CONNECTION_NOT_FOUND`。

新写入且明确识别为正常的无证据握手步骤默认保留 48 小时。准入、逐次认证、异常、关闭和旧版明细默认保留 30 天。连接摘要从最后一次接收起保留 30 天。普通握手过期后，仍可通过摘要检查累计步数和最后阶段，通过认证事件的 `credentialArtifactId` 访问权限范围内的证据。

MSSQL 的 `ProtocolViolation` 原始步骤可包含固定 `protocolErrorCode`。连接详情使用该码显示失败阶段，普通登录拒绝继续通过 `authenticationFailureCode` 返回 `18456`。历史事件没有分阶段错误码时继续显示原摘要。[协议认证补全实施方案](../spec/协议认证补全实施方案.md)

## 认证证据访问

证据摘要接口对已登录用户开放，仅返回来源、协议、材料类型、关联 ID、采集和留存时间等元数据。证据原文接口根据当前 Bearer 会话在服务端验证 `Administrator` 角色（兼容旧 `admin`，忽略大小写），返回 `data.summary` 和 `data.content`，并设置 `Cache-Control: no-store`。前端使用同一服务端角色合同；页面显示不能替代服务端权限检查。

应用已初始化时，无有效会话返回 HTTP 401，非管理员请求原文或审计返回 HTTP 403，管理员请求不存在或已过期的证据返回 HTTP 404 和 `NOT_FOUND_OR_EXPIRED`。原文访问审计写入 SQLite，审计接口最多返回最近 10,000 条有效记录内的访问人、时间、证据 ID 和结果。审计写入失败时返回 `EVIDENCE_AUDIT_FAILED`。RDP NTLM 证据保存收到的挑战和响应，材料类型为 `Response`。

原文导出请求形如 `{ "artifactIds": ["cred-00000000000000000000000000000001"] }`。每批最多 8 个不同的证据 ID，请求正文最多 4 KiB。只有管理员可调用；不合法的批次返回 HTTP 400。成功时 `data.items` 按请求顺序返回 `artifactId`、`outcome`，状态为 `OK` 的项目包含 `evidence.summary` 和 `evidence.content`。已过期或不存在的项目标记为 `NOT_FOUND_OR_EXPIRED`，不返回原文。响应设置 `Cache-Control: no-store`，审计用 `operation` 区分 `Read` 和 `Export`，不保存材料原文。

## 密码簿查询

`GET /api/v1/password-book?keyword=ssh&page=1&pageSize=20` 返回 `username / adapterKey / authenticationCount / lastUsedAtUtc / credentialArtifactId`，按最近一次认证尝试时间降序。可选的 `keyword` 按账号或服务做字面子串匹配，筛选作用于分页和总数。未登录和普通用户分别返回 HTTP 401 和 403，管理员查询响应使用 `Cache-Control: no-store`。

分页接口只返回元数据。管理台使用每行的代表证据 ID 读取当前页密码，CSV 导出复用 `POST /api/v1/credential-evidence/export`。每次原文访问独立审计。密码簿从 SQLite 中的有效证据计算，过期证据不计入次数。纳入条件见 [密码簿实施方案](../spec/密码簿实施方案.md)。

## 规划接口

服务类型、服务人格、服务实例、监听器、连接、事件和威胁清单接口见[蜜罐管理与事件 API 草案](蜜罐管理与事件 API 草案.md)。

连接建立后先记录 `ConnectionAccepted`，再进入协议握手；事件查询必须保留 `listenerId`、`serviceInstanceId` 和目标端口，不能只按协议名称聚合。

管理台按单服务器、单适配器实例展示服务卡片；实例默认监听 `0.0.0.0`，端口可以配置多个。端口输入仅修改页面草稿，点击“应用端口”后才写入服务端；启动/停止共用一个按运行状态切换的按钮。

真实传感器上报、细粒度 RBAC、登录/封禁/解封事件告警和自动阻断接口尚未建立。事件详情、威胁档案、认证证据、证据访问审计和关键管理操作已接入 SQLite。部署完成情况以对应环境的验收记录为准。

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
- `PUT /api/v1/settings/ip-location`：管理员保存设置，立即使旧的来源 IP 解析任务和缓存失效。同一蜜罐落点可沿用上次成功结果，直到新设置查询成功。
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

## MCP 服务

管理接口统一在 `/api/v1/mcp` 下，只接受管理员登录会话，响应使用 `ApiResult<T>` 和 `Cache-Control: no-store`。

| 方法与路径（相对 `/api/v1/mcp`） | 合同 |
| --- | --- |
| `GET /settings`、`PUT /settings` | 读取设置及审计状态。PUT 接收 `enabled` 或 `auditRetentionDays`，省略字段保持现值；留存默认 30 天，可设 1–365 天。 |
| `GET /permissions` | 返回业务分组、权限叶子和可选择的现有实例。 |
| `GET /keys`、`POST /keys` | 分页或创建。创建接收 `name / access / permissionIds / instanceIds / expiresAtUtc`，有效期省略为永久；HTTP 201 的 `data` 返回 `key` 和一次性 `secret`。 |
| `POST /keys/{id}/revoke`、`DELETE /keys/{id}` | 吊销、删除。未吊销时删除返回 HTTP 409；删除不影响历史审计。 |
| `GET /audits`、`GET /audits/{id}` | 查询审计摘要或详情。列表支持 `page / pageSize / keyId / tool / sourceIp / result / fromUtc / toUtc`，时间范围为 `[fromUtc,toUtc)`。 |

远程客户端连接 `/mcp`，选择 Streamable HTTP，设置 `Authorization: Bearer <API_KEY>`。该端点使用标准 MCP JSON-RPC；`tools/list` 只返回此 Key 可用的工具，`tools/call` 独立复核权限。工具执行失败可能返回 HTTP 200，客户端应检查 MCP `isError`。Key 不能访问管理 REST，登录会话也不能用于 MCP。

不支持通过 URL 传递 Key。请求上限 32 KiB，工具结构化结果上限 72 KiB，审计响应捕获上限 256 KiB。异常报文、超限内容以及凭据字段的处理方式见 [MCP 服务实施方案](../spec/MCP%20服务实施方案.md)。
