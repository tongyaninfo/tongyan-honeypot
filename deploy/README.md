# 部署说明

本目录只保留部署边界与占位说明，不包含服务器地址、凭据或证书。蜜罐监听端口属于宿主网络入口，部署前必须确认隔离程度、监听面、运行账号、数据卷、日志留存、回滚版本与健康检查。

## 运行形态

后端为单个 ASP.NET Core 宿主（`Honeypot.Api`），管理台是静态产物，可由同一宿主托管或由反向代理单独托管。应用不需要外部数据库进程，SQLite、通知设置、加密证据与 Syslog 暂存都位于 `Honeypot:DataDirectory`。

```bash
# 构建管理台
(cd frontend && npm ci && npm run build)

# 启动后端，数据目录与静态资源目录通过参数指定
dotnet run --project backend/src/Honeypot.Api/Honeypot.Api.csproj --no-launch-profile -- \
  --urls http://0.0.0.0:5080 \
  --webroot /srv/honeypot/wwwroot \
  --Honeypot:DataDirectory=/var/lib/honeypot
```

首次启动会在数据目录初始化 SQLite，并按页面提示创建首个管理员。创建服务实例后，只有确认绑定地址与端口范围，才应启动监听。

## 部署前确认

- **网络隔离**：诱捕端口与管理面分开规划；管理面经 HTTPS、反向代理或来源白名单限制访问，不直接暴露到公网。
- **最小权限**：运行账号只拥有数据目录与静态资源的读写权限；不要用 root 运行。
- **数据卷**：数据目录、保护密钥目录（`Honeypot:NotificationKeyDirectory`）与备份目录独立挂载，目录权限最小化。
- **端口与上限**：为每个监听实例设置绑定地址、并发连接与单连接字节上限；规划日志与暂存容量。
- **外部投递**：Syslog、SMTP 与 IP 归属地默认关闭，按需配置；TLS 默认校验服务端证书。
- **备份与回滚**：升级前备份数据目录与保护密钥；应用启动会执行 SQLite 迁移，回滚需要保留旧版本与对应备份。
- **健康检查**：`GET /health` 用于存活探测，不代表监听端口或外部投递已验证。

## 制品组成

```text
backend/       Honeypot.Api 发布产物（含依赖与运行时策略）
frontend/dist  管理台静态产物
docs/          产品文档（随源码仓库发布，不随运行包必需）
scripts/       协议与运行验证脚本
```

## 未提供

详细的主机清单、系统服务单元、容器编排与证书签发流程不在本仓库中，需要按实际环境单独制定并验证。示例中出现的地址与主机名均为占位符或文档保留网段。
