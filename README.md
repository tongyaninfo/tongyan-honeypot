# 通研 Honeypot

**通研官网**：<https://www.tongyaninfo.com>　|　**产品官网**：<https://honeypot.tongyaninfo.com>

通研 Honeypot 是面向隔离网络的单机蜜罐与威胁观测平台。它在指定端口模拟常见服务，记录连接、协议交互和认证尝试，并将同一来源 IP 的活动汇总到威胁清单。运维人员可以从总览定位异常，再回看连接细节、生成运行报告或把日志转发给集中日志平台。

[产品功能](#产品功能) · [快速开始](#快速开始) · [数据与运行边界](#数据与运行边界) · [开发与文档](#开发与文档) · [文档中心](docs/README.md) · [变更日志](CHANGELOG.md)

> 本项目为开源版本，源码以 [Apache License 2.0](LICENSE) 发布，第三方组件与商标说明见 [NOTICE](NOTICE)。
>
> 以下图片截取自实际管理台。截图使用隔离环境和合成数据，地址、账号、主机名和事件均为演示值；来源地址采用文档保留网段（`192.0.2.0/24`、`198.51.100.0/24`、`203.0.113.0/24`）。

当前源码版本为 [0.1.0](VERSION)，处于首批实现阶段，尚未封版。

## 产品功能

### 运行总览

查看实例与监听状态、活动连接、认证失败、威胁 IP 和进程资源。鼠标悬停在 24 小时趋势图上会显示横纵准线、该小时的连接数、认证失败数和采集覆盖。管理台通过 SignalR 刷新运行状态和事件。

在活动连接、近 24 小时接纳连接、今日认证失败或威胁 IP 指标上悬停，可展开带归属地的连接明细并翻页。威胁 IP 按来源各展示最近一条留存连接。认证失败详情显示账号，管理员可查看已采集的密码。

「全球连接地图」默认显示最近 10 分钟的已定位来源，可用滚轮或触摸板缩放、按住地图拖动，也可全屏查看。新连接默认实时播放，按服务类型配色，并支持暂停飞线及切换时间范围。启用 IP 归属地解析并选择支持经纬度的数据源后即可使用。[IP 归属地解析](docs/spec/IP归属地异步解析方案.md) · [蜜罐落点配置](deploy/README.md#实时飞线地图落点)

点击「协议活动」中的非零数字可查看对应明细和 IP 归属地。「优先排查来源」显示风险分最高的 8 条来源。

![运行总览：监听状态、认证失败、威胁 IP、趋势和协议分布](docs/images/overview.png)

### 多协议服务与监听

按协议管理服务实例，为同一实例配置多个监听端口。端口修改采用草稿与应用流程，页面可查看绑定状态、活动连接和错误数。保存重启自动启动策略后，再次进入页面会显示已保存的状态。

![服务实例：协议列表、运行状态与监听端口](docs/images/services.png)

内置 **16 种协议适配器**：

| 类别 | 协议 |
| --- | --- |
| 远程接入 | SSH、RDP、Telnet |
| 数据库与数据服务 | MySQL、MSSQL、MongoDB、PostgreSQL、Redis、Oracle、Db2、Memcached、HBase、InfluxDB、Elasticsearch |
| 文件共享 | SMB、NFS |

适配器按协议完成受控握手或认证交互，默认按 `AlwaysFail` 策略拒绝认证。NFS 模拟授权拒绝。各协议支持的交互深度和客户端验证范围见 [数据库与系统适配器扩展方案](docs/spec/数据库与系统适配器扩展方案.md) 与 [协议认证补全实施方案](docs/spec/协议认证补全实施方案.md)。

### 威胁事件与来源档案

威胁事件按来源和事件类型查询。打开一条活动即可查看同一连接的事件步骤、目标端口、认证方式和结果，并可导出 Excel。威胁清单按来源 IP 汇总活动次数、风险分、涉及协议和端口，便于从来源回到相关事件。

![威胁事件：连接和认证活动、来源、目标端口与结果](docs/images/events.png)

![威胁清单：按来源 IP 聚合的风险档案](docs/images/threats.png)

认证证据列表显示材料类型、采集状态和留存时间。管理员可以按权限查看或导出证据原文，读取操作有审计记录。配置 IP 数据库后，来源地址可异步显示归属地，默认使用通研 IP 适配器（`ip.tongyaninfo.com`），也可通过管理台改为其他兼容数据库。

管理员可在「密码簿」查看账号及密码组合的尝试次数与最近使用时间，按账号或服务模糊搜索，并将匹配结果导出为 CSV。当前页显示和 CSV 导出中的原文读取均逐条审计。仅收到公钥、令牌或挑战响应的尝试不进入密码簿。详见 [密码簿实施方案](docs/spec/密码簿实施方案.md)。

### 运行报告与邮件通知

按今日、本周、本月或自定义时间查看连接和认证趋势、来源排行、协议分布、资源采样及统计覆盖度。管理员可手动发送报告，或通过 SMTP 订阅日报、周报和月报，并在邮件记录中查询处理状态。

![运行报告：统计周期、活动趋势与运行指标](docs/images/reports.png)

### Syslog 转发

通过 **系统管理 → Syslog 配置** 将蜜罐日志发送到集中日志平台。支持 UDP、TCP、TLS、RELP，最多配置三个目标。报文保留 0–7 级严重级别，主机名使用 `tongyan-honeypot-计算机名`，应用名按模块区分。

可选择已保存的目标发送测试消息。填写单行文本或留空使用默认内容，发送结果显示传输阶段和关联 ID。TLS 默认验证服务端证书。详见 [Syslog 接入与分级方案](docs/spec/Syslog日志接入与全模块分级方案.md)。

![Syslog 配置：转发目标、测试消息和投递状态](docs/images/syslog.png)

### MCP 服务

在 **系统管理 → MCP 服务** 为智能体启用接入并创建 API Key。每个 Key 可单独授予运行总览、威胁调查、报告和实例管理等工具权限。调用记录支持按来源 IP、Key、工具和结果筛选，并可配置留存天数。接入使用同源 HTTPS 的 `/mcp`。详见 [MCP 服务实施方案](docs/spec/MCP%20服务实施方案.md)。

## 快速开始

需要 .NET 10 SDK（以 [global.json](global.json) 为准）、Node.js 22 或更高版本及 npm。以下命令适用于 Bash 或 Zsh。

在项目根目录构建管理台，再使用新的本地数据目录启动应用。页面和 API 共用回环地址，管理端只监听 HTTPS：

```bash
(cd frontend && npm ci && npm run build)

honeypot_data_dir="$(mktemp -d)"
dotnet run --project backend/src/Honeypot.Api/Honeypot.Api.csproj --no-launch-profile -- \
  --urls https://localhost:5080 \
  --webroot "$PWD/frontend/dist" \
  --Honeypot:DataDirectory="$honeypot_data_dir"
```

打开本地管理台 `https://localhost:5080`，核对浏览器显示的证书指纹与启动日志后创建首个管理员。首次启动会在新数据目录中初始化 SQLite。可在另一终端运行 `curl -kfsS https://localhost:5080/health` 执行无凭据的本机连通性检查。创建服务实例后，请在隔离网络内确认绑定地址和端口再启动监听。

## 数据与运行边界

- **服务仿真**：当前是单机观测版本。适配器提供受控交互，不建立真实 Shell、桌面或数据库会话。风险分用于观测和分析，自动封禁尚未接入。
- **持久化**：SQLite 保存实例与监听配置、详细事件、威胁档案、加密认证证据、密码簿统计依据、业务审计以及报告和邮件记录。连接摘要、认证、异常和威胁档案默认保留 30 天，新增的正常握手明细默认保留 48 小时。认证原始证据按实例有效期加密保留，默认 30 天。报告事件、运行采样和本地业务审计默认保留 90 天。使用原数据目录和证据密钥重启即可继续查询。
- **外部投递**：Syslog、SMTP 通知和 IP 归属地查询默认关闭，可由管理员按需要配置。Syslog 转发运行日志、业务事件和审计元数据，认证材料原文仅走受控证据接口。
- **部署**：使用独立数据目录并限制监听范围。应用启动时会执行 SQLite 迁移，升级既有环境前请先备份并核对迁移。

## 开发与文档

后端采用 ASP.NET Core、EF Core SQLite 和 SignalR。管理台采用 React、TypeScript、Umi Max 与 Ant Design Pro。

```text
backend/    后端解决方案、协议适配器、运行时、管理 API 和测试
frontend/   管理台页面、路由和 API 客户端
docs/       产品需求、接口说明、设计方案和变更记录
deploy/     部署说明
rules/      规则与风险策略约定
sensors/    传感器与监听运行时约定
scripts/    协议与运行验证脚本
```

```bash
dotnet test backend/Honeypot.slnx

cd frontend
npm run lint
npm test
npm run build
```

- [文档中心](docs/README.md)
- [管理 API 约定](docs/api/README.md)
- [报告与邮件通知方案](docs/spec/报告邮件通知实施方案.md)
- [多协议服务适配与拟真设计](docs/spec/多协议服务适配与拟真设计.md)
- [部署说明](deploy/README.md)
- [变更日志](CHANGELOG.md)
- [安全策略](SECURITY.md)
- [参与贡献](CONTRIBUTING.md)
- [项目开发约定](AGENTS.md)

## 许可

本项目以 [Apache License 2.0](LICENSE) 发布。管理台沿用 Ant Design Pro 模板的部分资产，模板许可文本随仓库保存在 [frontend/LICENSE](frontend/LICENSE)（MIT）。第三方组件适用其各自许可证，详见 [NOTICE](NOTICE)。
