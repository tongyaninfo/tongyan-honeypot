# 参与贡献

感谢参与通研 Honeypot。本文说明开发环境、代码约定、提交要求与脱敏边界。

## 开发环境

- **.NET SDK** 10.0.x（根 `global.json` 固定为 10.0.300，可用 `rollForward` 使用更新的补丁版本）
- **Node.js** 22 或更高版本（`frontend/package.json` 要求 `>=22.0.0`）
- **SQLite** 由应用内嵌，无需单独安装
- 真实协议客户端（OpenSSH、MySQL、MongoDB Shell、sqlcmd、MSTSC/FreeRDP 等）为可选，只有做客户端兼容验证时才需要

## 本地验证

提交前请在仓库根目录运行与改动范围对应的检查：

```sh
# 后端：构建与测试
dotnet build backend/Honeypot.slnx
dotnet test backend/Honeypot.slnx

# 前端：类型与 lint、单元测试、构建
cd frontend
npm ci
npm run lint
npm test
npm run build
```

改动协议适配器时，请补充对应的报文夹具与失败路径测试；改动前端页面时，请在真实浏览器中检查控制台与网络请求。

## 代码约定

- 使用中文沟通与注释，代码标识符、命令和协议名称使用英文。注释说明触发条件、权限、状态变化与副作用，不复述代码。
- 分层：`Honeypot.Shared`（合同）→ `Honeypot.Protocol.Abstractions` → `Honeypot.Runtime` / `Honeypot.Protocols.*` → `Honeypot.Engine` → `Honeypot.Api`。公共合同不依赖宿主。
- HTTP 业务接口统一返回 `ApiResult<T>`（`success / code / message / data`），并保留真实 HTTP 状态码。长整型 ID 对外使用十进制字符串。
- 时间内部使用 UTC，对外使用带时区的 ISO 8601；前端默认按 `Asia/Shanghai` 展示。
- 前端只负责展示和调用 API，按钮隐藏不能替代服务端鉴权；不要把敏感材料写入 `localStorage` 或 URL。
- 新增协议只实现适配器和测试，不要在适配器中自行监听端口、写库或访问真实上游服务。

## 提交规范

提交信息采用 Conventional Commits：`type(scope): 描述`。

- `type`：`feat`、`fix`、`docs`、`style`、`refactor`、`perf`、`test`、`chore`、`ci`、`revert`
- 冒号后一个空格，描述 1–50 字中文
- 前端目录已配置 commitlint 与 lint-staged，提交时自动校验

## 脱敏与安全边界

- **不要提交真实凭据、内网地址或个人路径**：示例配置、测试夹具与文档只使用占位符和文档保留网段（`192.0.2.0/24`、`198.51.100.0/24`、`203.0.113.0/24`、`2001:db8::/32`）。
- **不要提交运行数据**：`data/`、`*.db`、日志、证书私钥、备份与构建产物已在 `.gitignore` 中排除，请勿强制加入。
- **观测数据不进日志**：攻击者提交的密码与认证材料只进入加密证据仓库，不进入普通日志、指标、异常堆栈或接口返回。
- **修改认证策略需评估安全影响**：默认 `AlwaysFail` 是产品安全前提，任何可能建立真实会话的改动都必须在方案文档中说明并经过评审。
- 提交前请自查是否误带了本地环境文件、绝对路径或调试输出。

## 文档

- 方案与设计放在 `docs/spec`，架构决策放在 `docs/adr`，接口约定放在 `docs/api`。
- 文档必须区分规划、已实现、已验证和已部署，不能用代码存在推导功能已上线。
- 相对路径优先，不写个人绝对路径、凭据和生产连接串。
