# MCP 服务实施方案

日期：2026-11-11。状态：已实现并完成隔离验证。三表迁移与隔离测试已覆盖；实际运行库迁移、部署、开放公网和创建真实 API Key 不在本方案范围内，见“验证与回滚”。

## 接入与管理页面

在「系统管理」新增「MCP 服务」（`/system/mcp`），沿用现有管理员角色和 Ant Design 主题。两个 Tab 分别是「MCP 服务」和「调用记录」。

| 页面 | 设计 |
| --- | --- |
| MCP 服务 | 顶部显示运行状态、当前接入 URL、启动/停止按钮。初始关闭，设置随重启保留；停止后拒绝新 MCP 请求，已开始的调用按原超时完成并记录结果。管理页面、审计查询和蜜罐监听正常运行。 |
| API Key 列表 | 紧凑表格显示名称、标识前缀、只读/读写、授权数量、状态、创建/过期/最近调用时间。行操作：查看权限、复制接入指令、吊销；只有吊销后才能删除，历史审计保留。已过期的 Key 也可以先吊销再删除。 |
| 新建 API Key | 名称必填，默认只读，有效期留空为永久。按业务模块展开可勾选的权限树，默认无权限，至少勾选一个叶子；只读模式禁用并清除写权限。选择实例写权限时，另选允许控制的已有实例。提交后一次性展示明文，列表只显示前缀。名称、权限、实例范围、有效期均不可编辑。 |
| 调用记录 | 顶部放筛选和留存设置，支持按时间、Key、工具、来源 IP 和结果筛选。`size=small` 分页表固定结果列，行内显示北京时间（到秒）、调用对象、来源 IP、状态和耗时；点击打开侧边详情，分「概览 / 请求头 / 请求参数 / 响应」并可复制各段。列表不拉取大正文。 |

## MCP 协议与 API Key

- 在现有 ASP.NET Core 同源入口挂载 `/mcp`，使用官方 `ModelContextProtocol.AspNetCore` 2.3.1 的无状态 Streamable HTTP，验收 `2026-07-28` 及 `2025-11-25` 客户端。管理 REST 保持 `ApiResult<T>`，`/mcp` 使用 MCP 的 JSON-RPC 和工具结果。协议由 SDK 处理，未支持的方法按协议返回，不落到 SPA 页面。[C# SDK 协议兼容性](https://csharp.sdk.modelcontextprotocol.io/v2/versioning.html) · [C# SDK 传输](https://csharp.sdk.modelcontextprotocol.io/v2/concepts/transports/transports.html)
- `/mcp` 每次校验 `Authorization: Bearer <API_KEY>`、服务开关、过期和吊销状态，Key 与网页登录会话不可混用。服务端维护单一工具目录，权限树和 `tools/list` 从同一目录生成；`tools/call` 按工具和资源范围再次鉴权，猜到工具名也不能绕过。按 Key 和来源限制请求速率、并发、报文大小、查询条数和执行时长。过期和吊销即时阻止新调用；不会因服务重启而恢复。
- 使用密码学安全随机数生成 Key。SQLite 只保存公开标识前缀和随机密钥的不可逆摘要，验证时固定时间比较；不提供明文读取、编辑或找回。创建响应、详情和审计接口使用 `Cache-Control: no-store`。密钥不进入 URL、浏览器持久存储或普通日志。
- 「复制接入指令」从 `window.location.origin` 取协议、主机、非默认端口，再拼接 `/mcp`。例如后台在 `https://honeypot.example.invalid:8443/system/mcp`，复制内容的 Base URL 为 `https://honeypot.example.invalid:8443`，端点为 `https://honeypot.example.invalid:8443/mcp`。指令引导智能体按当前客户端格式注册 Streamable HTTP 远程服务，从客户端安全配置读取 `HONEYPOT_MCP_API_KEY`，带 Bearer 请求头连接并用 `tools/list` 检查权限；指令只含变量引用，实际 Key 从创建成功弹窗另行复制。剪贴板不可用时显示可选中的文本。
- 内网直连 HTTP 和 HTTPS 均支持。HTTP 限回环或部署时明确允许的隔离网络；远程接入使用 HTTPS，由 Kestrel 或受信反向代理终止 TLS。管理台浏览器可访问的 origin 必须能转发 `/mcp`，开发代理同样补齐。校验 Host、Origin；只从明确受信的代理处理转发协议与地址，审计取处理后的 `RemoteIpAddress`。[ASP.NET Core 代理与转发头](https://learn.microsoft.com/en-us/aspnet/core/host-and-deploy/proxy-load-balancer?view=aspnetcore-10.0)
- API Key 是本系统为受控客户端提供的 Bearer 凭据；接入客户端须支持自定义鉴权头。只支持 OAuth 自动授权的客户端不在本期兼容范围。[MCP Authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)

## 工具与授权树

调用应用层服务，复用现有查询、监听管理、报告计算和验证逻辑。公开的是明确的业务工具，不提供通用 HTTP 转发、Shell、SQL 或任意网络访问。工具返回结构化结果，观测到的用户名、主机名和其他文本是非可信业务数据。读写 Key 也必须逐项勾选授权。

| 权限树模块 | 只读工具（每个为可独立授权的叶子） | 写工具（每个为可独立授权的叶子） |
| --- | --- | --- |
| 运行总览 | `get_overview`：运行指标、监听统计、协议分布、趋势 | — |
| 服务与监听 | `list_service_types`、`list_service_instances`、`get_service_instance`、`list_listeners`：协议能力、实例配置与绑定状态 | `start_service_instance`、`stop_service_instance`、`set_service_restart_policy`：仅管理创建 Key 时选定的既有实例；启动或设置自动启动时核对获准的绑定配置，绑定变化需管理员重新授权，工具不接收绑定地址或端口 |
| 威胁事件 | `list_threat_events`、`get_connection_timeline`：筛选事件、回看连接步骤；`preview_threat_decision`：用已知观测字段预览当前规则判定，不触发采集或处置 | — |
| 威胁来源 | `list_threat_sources`、`get_threat_source`：按风险和 IP 查看档案 | — |
| 认证证据 | `list_credential_evidence_summaries`：关联 ID、材料类型、采集与留存等元数据 | — |
| 运行报告 | `get_operation_report`、`list_report_history`、`get_report_snapshot`：今日/周/月/自定义周期与历史快照 | `queue_operation_report`：给管理员预设的默认收件人排队发送报告；不接受收件人参数，复用现有配额和发送队列，按调用方请求标识防止重试重复入队 |
| 系统运行状态 | `get_syslog_status`、`list_report_mail_deliveries`：转发状态、邮件任务状态摘要 | — |

实例启停与启动策略由管理 REST 和 MCP 共用同一操作服务，针对同一实例串行处理并在执行时重新检查绑定配置，防止并发覆盖。查询使用分页和明确的输出字段，避免直接序列化实例内部配置或未经校验的原始载荷。

账号、MCP 管理、原始认证证据及其导出、SMTP/Syslog 目标配置、手填收件人发送与邮件重试、监听绑定变更继续由管理台处理。现有代码没有自动封禁执行能力；MCP 不增加此类工具。威胁事件、来源档案和证据摘要仍受现有进程内存储的历史范围限制；报告读取沿用现有 SQLite 和采集覆盖度口径。

## 调用审计与留存

- 对 `/mcp` 的协议请求记录调用时间、可信来源 IP、客户端、HTTP 方法和路径、协议版本、请求/关联 ID、Key 标识和名称快照、工具、结果、HTTP 状态、协议或业务错误、耗时和字节数。合法业务请求的普通请求头、请求参数、响应头及响应体原样保留，IP 不脱敏。协议成功但工具返回错误时单独显示工具失败。鉴权失败、无权调用、停用、校验失败和限流也记录结果；无法识别 Key 时显示未知。
- `Authorization`、Cookie、代理凭据、明文 API Key、密码、可复用票据和原始认证证据不落审计库。保留头名和「凭据未记录」标记；无效报文只保留可安全解析部分和错误信息。内容设字节上限并标明缺失/超限原因。工具先按白名单生成业务结果，日志详情将正文以纯文本或 JSON 渲染。详情只允许管理员访问，不将正文转发到 Syslog；Syslog 仅记录管理操作和故障摘要。
- 留存默认 30 天，可设 `1–365` 天。按 UTC 时间索引分批清理，到期记录从查询中即时排除。降低留存前显示将清理的时间范围，由管理员保存确认；后台继续清理，即使 MCP 已停止。删除 Key 不连带删除审计。
- 写工具执行前先持久化审计起始记录，登记失败时拒绝执行。执行后追加结果；若进程或结果写入异常，保留起始记录并明确标为结果未知，不自动重放写操作。数据库不可用时标记审计故障并在管理台提示；超出请求限额的流量仅在存储预算内留审计，超限量用计数记录。

## 管理接口与 SQLite 变更

管理接口统一放在 `/api/v1/mcp` 下，复用现有网页登录和后端 Administrator 校验。复用集中资源 ID 生成入口、统一分页和 UTC 时间合同。

| 接口 | 用途 |
| --- | --- |
| `GET /settings`、`PUT /settings` | 读取状态、启停和保存审计留存天数 |
| `GET /permissions` | 获取权限树和可授权的实例 |
| `GET /keys`、`POST /keys` | 列表和新建 |
| `POST /keys/{id}/revoke`、`DELETE /keys/{id}` | 吊销和删除已吊销 Key |
| `GET /audits`、`GET /audits/{id}` | 审计摘要分页和详情 |

只新增以下三张表与必要索引，不改现有表和数据。源码迁移及隔离 SQLite 升级测试需确认。当前应用启动时自动执行迁移，因此不能直接以现有数据目录启动新版程序来试跑；实际运行库的升级与部署另行确认。

| 新表 | 内容 |
| --- | --- |
| `mcp_settings` | 单行配置：服务启停、审计留存天数、变更时间和管理员 ID |
| `mcp_api_keys` | Key ID、唯一公开前缀、不可逆摘要、名称、模式、授权叶子和实例范围、创建/过期/吊销/最近调用时间 |
| `mcp_call_audits` | 调用元数据、Key 快照、请求和响应详情、审计状态；按时间、Key、工具及结果建立查询索引，不设删除级联 |

## 验证与回滚

1. 仅用临时 SQLite 验证从既有迁移升级、原实例/监听/报告数据保留、启停与 Key 状态重启保留、审计留存和删除 Key 后历史可读。用合成凭据和数据验证凭据从未进入审计库、日志或 Syslog。
2. 用真实 MCP 客户端库走本机 HTTP 和隔离 HTTPS，覆盖两个协议版本的发现、列工具和工具调用，检查只读 Key 直接调用写工具失败、未授权资源不可写、停用/过期/吊销立即拒绝、请求来源不能被伪造转发头替换。监听启停使用回环监听或测试替身，邮件使用隔离队列或替身验证收件人边界与防重。验证审计故障时不会执行新写操作。
3. 运行 `dotnet test backend/Honeypot.slnx` 和前端 `npm run lint`、`npm test`、`npm run build`。在浏览器检查两 Tab、授权树、紧凑列表与详情、窄屏、HTTP 复制回退及 HTTPS 复制，使用合成数据验收。
4. 回滚先关停 MCP，再按目标环境验证过的方式切回旧制品，保留新增表和审计记录，不使用向下迁移删表。实际升级前备份数据目录并验证旧制品读取兼容性。
