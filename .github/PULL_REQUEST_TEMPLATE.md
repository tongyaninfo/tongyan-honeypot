## 改动说明

<!-- 说明改动的目的、范围和影响。 -->

## 涉及范围

- [ ] 后端管理 API 与宿主（`backend/src/Honeypot.Api/`）
- [ ] 协议适配器（`backend/src/Honeypot.Protocols.*/`、`backend/src/Honeypot.Protocol.Abstractions/`）
- [ ] 监听运行时（`backend/src/Honeypot.Runtime/`）
- [ ] 判定引擎与公共合同（`backend/src/Honeypot.Engine/`、`backend/src/Honeypot.Shared/`）
- [ ] 前端管理台（`frontend/`）
- [ ] 部署与配置（`deploy/`、`appsettings*.json`）
- [ ] 文档（`docs/`、`README.md`、`CHANGELOG.md`）
- [ ] 规则与传感器约定（`rules/`、`sensors/`）
- [ ] 脚本与 CI（`scripts/`、`.github/`）

## 验证

<!-- 列出实际运行的命令与结果；未运行的检查请注明原因。 -->

```sh
# 示例
dotnet build backend/Honeypot.slnx
dotnet test backend/Honeypot.slnx --no-build
cd frontend && npm run lint && npm test && npm run build
```

## 安全与脱敏

- [ ] 未包含真实主机、内网地址、账号、口令、Token、私钥或真实观测记录
- [ ] 截图与示例数据为合成内容，来源地址使用文档保留网段
- [ ] 涉及认证策略、证据留存、监听端口、SMTP 凭据或 Syslog 转发的改动已说明威胁边界
- [ ] 未在真实网络或生产环境开放监听端口做试验
