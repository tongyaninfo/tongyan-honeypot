# syntax=docker/dockerfile:1
# 通研 Honeypot 单机镜像：前端静态产物 + ASP.NET Core 管理 API。
# 构建阶段使用 $BUILDPLATFORM（构建机原生平台）执行编译，运行阶段使用 $TARGETPLATFORM，
# 便于在 Apple Silicon 上用 `--platform linux/amd64` 交叉产出 amd64 镜像而无需模拟执行编译。
# 构建上下文为仓库根目录；不包含数据目录、密钥或本地运行时文件。

FROM --platform=$BUILDPLATFORM node:24.17.0-alpine AS frontend
# 默认使用官方 npm 源；网络受限环境可在构建时通过 --build-arg NPM_REGISTRY=<镜像源> 覆盖。
ARG NPM_REGISTRY=https://registry.npmjs.org
WORKDIR /src/frontend
# 先复制锁文件安装依赖，保留层缓存；prepare 脚本依赖 .git，镜像内没有 .git，故跳过生命周期脚本。
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --registry="$NPM_REGISTRY" --ignore-scripts --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

FROM --platform=$BUILDPLATFORM mcr.microsoft.com/dotnet/sdk:10.0 AS backend
WORKDIR /src
COPY global.json ./
COPY backend/ ./backend/
# 目标运行环境是 linux-x64（部署宿主与镜像仓库均为 amd64），
# 由构建机 SDK 交叉发布，不依赖构建机架构。UseAppHost=false 避免生成多余启动器。
RUN dotnet publish backend/src/Honeypot.Api/Honeypot.Api.csproj \
      -c Release -r linux-x64 --self-contained false \
      -p:UseAppHost=false -o /publish
COPY --from=frontend /src/frontend/dist /publish/wwwroot

FROM --platform=$TARGETPLATFORM mcr.microsoft.com/dotnet/aspnet:10.0 AS runtime
WORKDIR /app
COPY --from=backend --chown=app:app /publish/ ./
ENV ASPNETCORE_ENVIRONMENT=Production \
    ASPNETCORE_HTTP_PORTS="" \
    Honeypot__DataDirectory=/app/data \
    DOTNET_CLI_TELEMETRY_OPTOUT=1 \
    TZ=Asia/Shanghai
EXPOSE 5080
USER app
ENTRYPOINT ["dotnet", "Honeypot.Api.dll", "--urls", "https://0.0.0.0:5080"]
