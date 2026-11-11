# 变更记录

本项目的显著变更记录在此文件中。格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本号遵循[语义化版本](https://semver.org/lang/zh-CN/)。源码版本以根 [VERSION](VERSION) 为准。

## [Unreleased]

### 计划中

- 真实传感器接入与抓包/eBPF 侧事件补全。
- 风险规则的版本化发布流程（草稿 → 观察 → 生效 → 回滚）。
- 详情事件、来源风险档案与认证证据由进程内存储迁移到可持久化实现。

## [0.1.0] - 未封版

首个开源版本，工程初始化阶段。

### 新增

- **后端分层**：`Honeypot.Shared`（合同）、`Honeypot.Protocol.Abstractions`、`Honeypot.Runtime`（统一 TCP 监听与端口实例）、`Honeypot.Protocols.*`（协议适配器）、`Honeypot.Engine`（判定与威胁聚合）、`Honeypot.Api`（管理 API、SignalR 与健康检查）。
- **16 种协议适配器**：SSH、RDP、Telnet、MySQL、MSSQL、MongoDB、PostgreSQL、Redis、Oracle、Db2、Memcached、HBase、InfluxDB、Elasticsearch、SMB、NFS。默认 `AlwaysFail` 认证策略，进入认证阶段后返回协议合法的登录失败，不建立真实会话。
- **监听与端口管理**：一个服务实例支持多个监听绑定，端口修改采用草稿与应用流程，可查看绑定状态、活动连接与错误数，可设置服务重启后的启动策略。
- **事件与威胁清单**：连接、握手、认证、规则与关闭事件；按来源 IP 聚合风险档案，支持查询与导出 Excel。
- **认证证据**：原始认证材料进入加密证据仓库，按权限、留存与审计控制访问，读取与导出写入审计。
- **运行报告与邮件通知**：今日/本周/本月/自定义区间报告，统计覆盖度、趋势与排行；SMTP 日报/周报/月报订阅与邮件记录，授权码使用 AES-GCM 加密存储。
- **Syslog 转发**：UDP、TCP、TLS、RELP 四种传输，最多三个目标，0–7 级严重级别，标准报头主机名 `tongyan-honeypot-计算机名`，支持测试消息与投递状态。
- **IP 归属地**：默认集成通研 IP 适配器（`ip.tongyaninfo.com`），可在管理台切换协议、主机、端口、数据库与超时；归属地异步补齐，不阻塞列表加载。
- **实时刷新**：通过 SignalR 推送运行状态与事件。
- **管理台**：React 19 + Umi Max 4 + Ant Design 6 + Ant Design Pro 6 管理台，覆盖运行总览、服务实例、运行报告、威胁事件、威胁清单、认证证据、系统管理与首次初始化。
- **开源工程文件**：Apache License 2.0、NOTICE、CONTRIBUTING、SECURITY、CHANGELOG、GitHub Actions CI 与 Issue/PR 模板。

### 已知边界

- **服务仿真而非真实服务**：适配器提供受控交互，不建立真实 Shell、桌面或数据库会话；风险分用于观测与分析，自动封禁尚未接入。
- **部分状态在进程内**：详细事件、来源风险档案与加密认证证据目前采用进程内存储，服务重启会清空；SQLite 只保存实例与监听配置、报告字段、资源采样、报告快照与邮件任务。
- **外部投递默认关闭**：Syslog、SMTP 通知与 IP 归属地查询默认关闭，需由管理员显式配置。
- **未完成真实验收**：真实传感器接入、公网监听、真实客户端全矩阵兼容、容量与持续负载、现场部署均未验证。本版本只在本机隔离环境与合成数据下验证。
- **单机形态**：当前为单机观测版本，尚无多节点聚合、集中身份服务与规则发布平台。
