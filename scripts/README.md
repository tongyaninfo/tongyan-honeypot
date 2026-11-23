# 验证脚本

脚本必须可重复、默认只读或只写隔离目录，不读取无关密钥，不执行 Git 操作。后续可在此增加：

- `verify-backend`：编译、单测和 API 合同检查；
- `verify-frontend`：lint、test、build；
- `replay-events`：使用脱敏样本离线回放规则；
- `check-docs`：检查文档链接、路径和状态描述。

- [企业数据库原生客户端回环验收](enterprise-auth-client-probes/README.md)：Oracle、Db2、HBase 标准认证失败与证据关联检查。

## SQLite 隔离容量验收

从仓库根目录运行，数据在新建的系统临时目录内。夹具使用文档保留地址、合成账号、临时证据密钥和旧版表结构。运行程序会在这个目录完成 SQLite 迁移，并通过 TestServer 调用实际管理 API。回放以事件接收器作为数据入口，不建立对外协议连接。协议入口、故障切断与进程重启由后端集成测试单独验证。

```bash
project=backend/tests/Honeypot.Storage.LoadTest/Honeypot.Storage.LoadTest.csproj
dotnet build "$project" -c Release
fixture=$(dotnet run --no-build -c Release --project "$project" -- seed)
dotnet run --no-build -c Release --project "$project" -- full "$fixture"
```

`seed-small` 和 `smoke` 可用于快速验证。每个夹具仅运行一次。正式工况使用 65 万条历史步骤、7 万份可解密证据，需约 75 分钟加迁移、逐次解密对账时间。输出位于夹具目录的 `result.json`、`connections.csv` 和 `authentications.csv`。记录包含合成 ID 和校验结果。保留原始证据文件的目录含测试专用密钥，交付压测结果只需要上述三份文件。

压测进程正常退出、夹具已经关闭且没有待合并的 WAL 后，可独立核对两张事件表的单边缺行、连接序号、认证次序与证据关联。以下命令只读本工具生成的隔离库。

```bash
sqlite3 -bail -json "file:${fixture}/honeypot.db?mode=ro&immutable=1" \
  < backend/tests/Honeypot.Storage.LoadTest/reconcile-ledger.sql
```

## 首页查询快照对照

使用 SQLite 在线备份或已停稳的独立快照。将单文件快照只读挂载至无网络测试容器，分别对旧版、候选版运行相同测试程序。每个客户端每轮并发发起首页的五个 GET，包含管理鉴权、应用处理和响应序列化。参数中的 UTC 来自快照时间，最后两个参数是正式轮数和同时刷新首页的客户端数。

```bash
./Honeypot.Storage.LoadTest snapshot /snapshot/honeypot.db /results/before.json 2026-11-22T12:52:29Z 20 1
# 在候选版本的容器中执行
./Honeypot.Storage.LoadTest snapshot /snapshot/honeypot.db /results/after.json 2026-11-22T12:52:29Z 20 1
node backend/tests/Honeypot.Storage.LoadTest/compare-snapshot-benchmark.mjs /results/before.json /results/after.json
```

第一个请求单独记录；每轮截止时间推进五秒。对照工具核验两个目标接口每一轮的业务响应摘要，按原始毫秒样本计算 P50、P95、最大值，并汇总每个 SQL 模板在一次请求中的用时。多个旧版/候选文件对可以合并计算。任何响应不同或含首轮的目标接口 P95 达到 1 秒，程序均返回非零退出码。
