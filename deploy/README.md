# 部署说明

本目录只保留可复用的镜像构建、容器编排与 systemd 发布定义，**不包含服务器地址、账号、口令、证书或生产连接串**。宿主地址、镜像仓库地址、端口绑定等真实参数由部署环境的私有 `.env` 或服务器私有配置注入；参考 [`docker-compose/.env.example`](docker-compose/.env.example)。

## 部署形态

- **容器部署**：`docker-compose/compose.yaml` 定义单个管理容器，数据目录绑定宿主目录，镜像由 `dockerfile/` 构建后推送到部署环境的镜像仓库。
- **systemd 部署**：不使用容器，适合蜜罐需要直接占用宿主协议端口、且不希望引入容器运行时的场景。应用自带 .NET 运行时。
- 两种形态都强制管理端 HTTPS，首次启动在数据目录初始化 SQLite 并执行迁移。

蜜罐协议监听端口属于宿主网络入口，部署前必须确认隔离程度、监听面、运行账号、数据卷、日志留存、回滚版本与健康检查。

## systemd 部署（无容器，适合蜜罐直接监听端口）

蜜罐需要直接占用宿主协议端口、且不想在目标机引入容器运行时时使用。目标机只需 `systemd` 与 `openssl`（应用自带 .NET 运行时）。

```bash
# 1. 自包含发布（目标机无需安装 .NET）
cd <repo-root>
dotnet publish backend/src/Honeypot.Api/Honeypot.Api.csproj -c Release \
  -r linux-x64 --self-contained true -p:UseAppHost=true -p:NuGetAudit=false \
  -o /tmp/honeypot/publish
cp -R frontend/dist /tmp/honeypot/publish/wwwroot
tar czf honeypot-0.1.0-linux-x64.tar.gz -C /tmp/honeypot publish

# 2. 目标机：系统用户、目录、解压
useradd --system --home-dir /opt/honeypot --shell /sbin/nologin honeypot
mkdir -p /opt/honeypot/{app,data,certs}
tar xzf honeypot-0.1.0-linux-x64.tar.gz -C /opt/honeypot
mv /opt/honeypot/publish /opt/honeypot/app
chown -R honeypot:honeypot /opt/honeypot
```

**管理端强制 HTTPS**：`backend/src/Honeypot.Api/Common/ManagementHttps.cs` 会在启动时校验 `Urls` 与 `Kestrel:Endpoints`，任一为 `http://` 即抛异常退出。因此必须配置 `https://` 监听并提供证书：

```bash
# 固定自签证书（SAN 必须包含访问用的 IP/域名）
openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
  -keyout key.pem -out cert.pem -config <(cat openssl.cnf)   # SAN=DNS:localhost,IP:<host-ip>
openssl pkcs12 -export -out management.pfx -inkey key.pem -in cert.pem -passout "pass:<口令>"
# 上传到 /opt/honeypot/certs，属主 honeypot、600；口令写入 pfx.env（root:root 600）
```

systemd 单元要点：

```ini
[Service]
User=honeypot
WorkingDirectory=/opt/honeypot/app
Environment=ASPNETCORE_ENVIRONMENT=Production
Environment=ASPNETCORE_URLS=https://0.0.0.0:5080
Environment=Honeypot__DataDirectory=/opt/honeypot/data
Environment=Kestrel__Certificates__Default__Path=/opt/honeypot/certs/management.pfx
EnvironmentFile=/opt/honeypot/certs/pfx.env
ExecStart=/opt/honeypot/app/Honeypot.Api --urls https://0.0.0.0:5080
Restart=always
AmbientCapabilities=CAP_NET_BIND_SERVICE   # 允许后续蜜罐实例监听 1024 以下端口
NoNewPrivileges=true
PrivateTmp=true
```

放行端口：`firewall-cmd --permanent --add-port=5080/tcp && firewall-cmd --reload`。蜜罐协议端口按实例逐个放行，注意避开宿主已占用端口。

## 镜像构建

构建上下文为仓库根目录，`.dockerignore` 已排除依赖、构建产物、数据目录和文档。

| 文件 | 用途 |
| --- | --- |
| [`dockerfile/Dockerfile`](dockerfile/Dockerfile) | 标准多阶段构建：Node 构建管理台、.NET SDK 发布 API、aspnet 运行时装配。构建阶段使用 `$BUILDPLATFORM`、运行阶段使用 `$TARGETPLATFORM`，可在 Apple Silicon 上交叉产出 amd64 镜像。 |
| [`dockerfile/Dockerfile.runtime`](dockerfile/Dockerfile.runtime) | 装配式构建：只复制本机预构建的 `publish/`（已含 `wwwroot` 前端产物），适用于构建网络受限、无法在镜像内安装 npm 依赖的环境。 |

```bash
# 标准全量构建（在仓库根目录执行）
podman build --platform linux/amd64 -f deploy/dockerfile/Dockerfile \
  -t <harbor>/honeypot/api:0.1.0-<构建时间戳> .

# 网络受限时的装配式构建
dotnet publish backend/src/Honeypot.Api/Honeypot.Api.csproj -c Release \
  -r linux-x64 --self-contained false -p:UseAppHost=false -o /tmp/hp-image/publish
cp -R frontend/dist /tmp/hp-image/publish/wwwroot
mkdir -p /tmp/hp-image/data && touch /tmp/hp-image/data/.keep
cp deploy/dockerfile/Dockerfile.runtime /tmp/hp-image/Dockerfile
podman build --platform linux/amd64 --pull=never -f /tmp/hp-image/Dockerfile \
  -t <harbor>/honeypot/api:0.1.0-<构建时间戳> /tmp/hp-image
```

镜像以非 root 用户 `app`（UID 1654）运行，数据目录为 `/app/data`（`Honeypot:DataDirectory`）。**容器部署同样必须使用 `https://` 监听并提供证书**（见 `Kestrel__Certificates__Default__*`）；历史上以 `--urls http://...` 运行属启动校验未读取到命令行参数的巧合，不应再使用。容器内无 curl/wget，健康检查可用应用内置探针 `Honeypot.Api --probe-management-health` 或 bash `/dev/tcp`。

## 推送镜像仓库

部署环境的镜像仓库需提前创建 `honeypot` 项目。推送与拉取均通过部署环境的私有凭据完成：

```bash
docker login <harbor> -u <user>
docker tag <本地镜像> <harbor>/honeypot/api:<tag>
docker push <harbor>/honeypot/api:<tag>
```

仓库端校验：项目 `honeypot` → 仓库 `api` → tag `0.1.0-<构建时间戳>`；记录返回的 digest 供回滚核对。

## 容器部署（Docker Compose）

```bash
# 1. 部署目录与数据目录（属主 = 容器用户 app，UID 1654）
mkdir -p /opt/honeypot/data
chown -R 1654:1654 /opt/honeypot/data

# 2. 准备私有 .env（不提交）与 compose
#    HONEYPOT_IMAGE=<harbor>/honeypot/api:<tag>
#    HONEYPOT_WEB_BIND=<内网地址或 127.0.0.1>
#    HONEYPOT_DATA_DIR=/opt/honeypot/data

# 3. 启动并检查
cd /opt/honeypot
docker compose -p honeypot -f compose.yaml up -d
docker compose -p honeypot -f compose.yaml ps
```

首次访问 `https://<docker-host>:18082/`，核验证书后按页面提示创建首个管理员。应用启动时会在数据目录初始化 SQLite 并执行迁移。

### 端口与暴露

- 管理台 HTTPS 使用宿主 `18082` → 容器 `5080`，绑定地址由 `HONEYPOT_WEB_BIND` 决定。管理台在回环或管理网内访问。使用反向代理时，上游也改用 HTTPS，并配置服务器证书信任。
- 默认管理证书每次启动生成，SHA-256 指纹写入启动日志。SAN 默认包含 `localhost`、`127.0.0.1` 和 `::1`。用非回环 IP 或域名访问时可配置 `Honeypot__ManagementHttps__CertificateNames__0`，额外名称使用递增索引。需要保留证书指纹或让客户端自动验证证书时，用 `Kestrel__Certificates__Default__Path` 指定单独挂载的管理证书，密码从私有部署配置注入。
- 升级旧服务时，将启动参数及 Kestrel 端点的 `http://` 一并改为 `https://`。发现明文端点配置时应用会拒绝启动。变更端点或证书配置后重启应用。
- 蜜罐协议监听端口由平台内服务实例配置决定。Compose 只映射管理台，启用协议仿真时按实例端口追加 `ports` 映射并放行对应端口。

### 登录和采集资源限制

以下配置在启动时读取，可在 `appsettings.json` 或同名环境变量中覆盖。使用环境变量时，各层配置名以 `__` 分隔，例如 `Honeypot__LoginLockout__DurationMinutes`。

| 配置节 | 默认值和行为 |
| --- | --- |
| `Honeypot:LoginLockout` | `MaxFailedAttempts=5`、`DurationMinutes=30`。连续失败达到阈值后暂停系统的新登录。成功登录清零，锁定期间的请求不延长锁定，已有会话继续使用。截止时间保存到数据目录的 `login-lockout.json`。 |
| `Honeypot:ConnectionAdmission` | `MaxConcurrentConnections=512`、`MaxConcurrentConnectionsPerSource=24`、`MaxNewConnectionsPerSecond=120`、`MaxNewConnectionsPerSourcePerSecond=12`。所有蜜罐 TCP 端口共享这些额度，各监听自身的并发限制也继续生效。准入拒绝的连接也按连接 ID 记录原因。 |
| `Honeypot:Events` | `QueueCapacity=256` 控制内存排队。连接、认证及异常明细按 `DetailRetentionDays=30` 留存；新采集的正常握手按 `HandshakeRetentionHours=48` 留存。威胁档案、报告及审计分别由 `ThreatRetentionDays=30`、`ReportRetentionDays=90`、`AuditRetentionDays=90` 控制。 |
| SQLite 存储 | 库、WAL 和卷余量用于观测。历史 `DatabaseBudgetMiB`、`MinimumFreeDiskMiB`、`MaxStoredMiB` 已失效；SQLite 实际返回的空间、锁和 I/O 错误可由存储指标定位。 |
| `Honeypot:CredentialEvidence` | 已按协议输入边界采集的材料加密保留。每个实例的 `CredentialEvidenceRetentionDays` 默认 30 天。证据访问审计由 `AuditRetentionDays=90` 控制；密钥默认位于数据目录下的 `credential-evidence-keys`，也可由 `KeyDirectory` 指定。 |

服务实例的对外主机名、产品和版本字段只填写仿真值。协议使用单独生成的仿真证书，管理端证书仅用于管理端 HTTPS。管理 API 的 `/api/v1/metrics/summary` 可查询采集队列、拒写原因、锁重试及最近成功写入时间。

留存任务分批清理超期记录，SQLite 空闲页由后续写入复用。升级前暂停采集并备份数据目录，使用 SQLite 一致性备份。首次采集证据时创建专用密钥文件 `evidence-v1.key`。密钥目录单独挂载时，也须受控备份。重启、换容器或恢复备份时使用与数据库匹配的密钥。已有证据但找不到匹配密钥时，凭据读写会失败。

业务持久化迁移增加五张表和索引。旧报表记录保留在原表。需要回退应用版本时保留新表及密钥，避免使用反向迁移删除已经收集的记录。[持久化实施方案](../docs/spec/连接事件与威胁清单设计.md#11-详细事件威胁档案与密码簿持久化)

增量迁移 `20261119111011_ConnectionSummaries` 从真实连接明细回填摘要，新版正常握手使用短留。其他实例的切换和回退步骤见[SQLite 采集与查询整改](../docs/spec/SQLite采集与查询整改.md)。

### 实时飞线地图落点

在管理台「系统管理 → IP 数据库配置」启用解析，并选择提供经纬度的 `ip2location`、`geolite2` 或 `dbip`。地图仅使用当前数据源实际返回的有效坐标。

| 可选部署配置 | 作用 |
| --- | --- |
| `Honeypot__AttackMap__Target__Latitude`、`Honeypot__AttackMap__Target__Longitude` | 两项填写后优先使用手动坐标，范围分别为 `[-90, 90]`、`[-180, 180]`。 |
| `Honeypot__AttackMap__Target__PublicIp` | 未填写手动坐标时，可明确指定蜜罐的公网入口 IP。必须是公网地址。 |
| `Honeypot__AttackMap__Target__Label` | 在地图上展示的落点名称。 |

未配置手动坐标或公网入口时，启用 IP 定位的部署会从所选定位服务探测公网出口并定位。内网定位服务可能只看到蜜罐的私网地址，此时自动探测无法取得公网地址。成功落点缓存一天。到期或同一目标切换定位服务、数据库时，先显示上次成功的位置及其时间，再用当前设置重新查询。失败后每隔 15 分钟再试，成功后更新坐标和时间。持久缓存保存在数据目录的 `connection-map-target-cache.json`。关闭 IP 定位可停止自动探测和来源查询。

## 验证清单

```bash
docker compose -p honeypot -f compose.yaml ps                 # STATUS = healthy
curl -kfsS https://localhost:18082/health                    # 无凭据的本机连通性检查
curl -kfsS -o /dev/null -w '%{http_code}\n' https://localhost:18082/index.html
curl -kfsS https://localhost:18082/api/v1/setup/status        # 核对初始化状态
docker logs --tail 50 honeypot                                # 无未处理异常
docker exec honeypot ls -l /app/data                          # SQLite 文件可写
```

## 回滚

1. **镜像**：部署前记录旧 tag/digest。回滚旧镜像时同时恢复与该镜像匹配的 Compose 健康检查和反代上游设置，再执行 `docker compose -p honeypot -f compose.yaml up -d`。
2. **数据**：停写后备份 `/opt/honeypot/data`（SQLite 一致备份：`sqlite3 honeypot.db ".backup ..."` 或停容器后整目录复制），回滚镜像后恢复并核对迁移版本。
3. **compose**：保留上一版 `compose.yaml` 与 `.env` 副本，配置变更后重新 `up -d`。

## MCP 接入配置

MCP 复用管理台的 HTTPS 域名和端口。升级前备份数据目录，应用启动会执行新增的三表迁移。服务初始关闭，可由管理员在页面启用。使用反代时，需要通过 HTTPS 转发 `/mcp`，保留外部 `Host` 和 MCP 请求头，并关闭 Streamable HTTP 响应缓冲。

| 配置（环境变量写法） | 用途 |
| --- | --- |
| `Honeypot__Mcp__AllowedHosts__0` | 精确允许的非回环主机名、IP 或含端口的 Host。多项使用递增索引；不使用通配符。 |
| `Honeypot__Mcp__TrustedProxies__0` | 受信的代理 IP。仅从该代理接受一跳的 `X-Forwarded-For` 和 `X-Forwarded-Proto`；代理必须覆盖来自外部的同名头。 |
| `Honeypot__Mcp__AllowedInstanceBindAddresses__0` | 允许 MCP 启动或开启自动恢复的非回环实例绑定地址，填明确的隔离私网 IP。回环地址默认允许，通配地址不允许。 |

管理台显示和复制的是浏览器当前 origin。若管理 API 由不同站点提供，仍需让管理台的外部 origin 代理 `/mcp`。使用真实流量前验证反代传递的 IP 和协议、HTTPS 证书链、客户端 Bearer 请求头，以及 SQLite 审计留存所需空间。回滚先停止 MCP，再切回已验证兼容的旧制品，保留新增表。
