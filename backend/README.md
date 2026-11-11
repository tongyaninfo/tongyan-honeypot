# Honeypot 后端

后端按 `Shared → Protocol.Abstractions → Runtime/Protocols → Engine → Api` 分层：公共合同不依赖宿主，监听运行时统一管理端口，协议适配器只处理协议拟真，判定引擎负责威胁聚合，API 负责管理和查询。报告所需事件白名单、运行采样、报告快照及邮件队列使用 SQLite 持久化；原事件列表、威胁档案和认证证据仍使用开发阶段内存实现。

## 运行

```bash
dotnet build backend/Honeypot.slnx
dotnet run --project backend/src/Honeypot.Api/Honeypot.Api.csproj --urls http://localhost:5080
```

## 目录约定

业务模型和 DTO 放 `Models/`，接口放 `Service/`，实现放 `Service/impl/`。新增协议只实现适配器和测试，不在适配器中自行监听端口、写库或访问真实上游。接入生产数据库、消息队列、密钥托管、真实传感器或 ID 服务前，先更新 `docs/spec` 并补充隔离验证。

## 报告邮件通知

报告统计、邮件模板和 SMTP 外发分别由独立服务处理，后台任务负责 30 秒运行采样、日历调度与持久化发件队列。HTML 模板放在 `src/Honeypot.Api/Resources/EmailTemplates/`，模板内容会随发布复制；页面和邮件使用同一报告数据合同。

通知总开关和日/周/月订阅默认关闭，SSL/TLS 默认开启。运行时配置位于 `Honeypot:DataDirectory` 下的 `notifications/settings.json`；授权码只存 AES-GCM 密文。保护密钥默认位于 `notifications/keys/smtp.key`，可通过 `Honeypot:NotificationKeyDirectory` 指定独立受控目录。备份和恢复必须同时保留数据库、通知设置及对应保护密钥，密钥缺失时禁止自动重建替换已有凭据。上述文件不进入仓库。

迁移 `20261110135715_ReportNotifications` 新增六张报告/通知表。应用启动自动迁移，因此现有运行环境升级前必须单独确认目标库与备份；本次仅验证隔离 SQLite，未迁移实际运行库或部署。完整接口、测试和限制见[报告邮件通知实施方案](../docs/spec/报告邮件通知实施方案.md)。
