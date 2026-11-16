# 镜像构建入口

构建上下文均为仓库根目录，`.dockerignore` 排除 `frontend/node_modules`、`frontend/dist`、`**/bin`、`**/obj`、`data/` 与本地运行时文件。

| 文件 | 适用场景 | 关键点 |
| --- | --- | --- |
| `Dockerfile` | 常规 CI/联网环境 | 多阶段：Node 构建管理台 → .NET SDK 发布 API → aspnet 运行时；构建阶段使用 `$BUILDPLATFORM`、运行阶段使用 `$TARGETPLATFORM`，不依赖 qemu 模拟编译；可用 `--build-arg NPM_REGISTRY=<镜像源>` 覆盖 npm 源。 |
| `Dockerfile.runtime` | 构建网络受限（如容器内 npm 依赖下载过慢） | 只装配本机预构建的 `publish/`（需已把 `frontend/dist` 复制为 `publish/wwwroot`），不在镜像内还原依赖；必须使用 `--platform linux/amd64`。 |

两套镜像均以非 root 用户 `app`（UID 1654）运行。容器内的管理端口 `5080` 使用 HTTPS。数据目录为 `/app/data`，环境为 `Production`，时区为 `Asia/Shanghai`。

```bash
# 标准构建
podman build --platform linux/amd64 -f deploy/dockerfile/Dockerfile -t <harbor>/honeypot/api:<tag> .

# 装配式构建（上下文目录需包含 publish/ 与 data/.keep）
cp deploy/dockerfile/Dockerfile.runtime /tmp/hp-image/Dockerfile
podman build --platform linux/amd64 --pull=never -f /tmp/hp-image/Dockerfile -t <harbor>/honeypot/api:<tag> /tmp/hp-image
```

构建后运行 `podman image inspect <镜像> --format '{{.Architecture}}'`，确认架构为 `amd64`。本地运行后通过 HTTPS 请求 `/health` 和 `/api/v1/setup/status`，核对应用与 SQLite 初始化状态。
