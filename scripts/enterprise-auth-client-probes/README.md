# 企业数据库真实客户端回环验收

此目录不启动真实数据库，不连接上游。`.NET` 验收宿主仅绑定 `127.0.0.1` 随机高端口，启动指定的客户端，检查标准认证失败、恰好一条关联认证证据及普通事件不包含口令。所有凭据均为代码中明确标记的隔离样本。

2026-11-10 验收版本：Oracle `python-oracledb 26.1.0` Thin、IBM JCC `11.5.9.0`（驱动 `4.33.31`）、HBase `hbase-shaded-client 2.5.13`、Java `1.8.0_491`、SLF4J API/NOP `1.7.36`。依赖放在独立虚拟环境或临时目录，不把 jar 或本地环境路径提交仓库。

在仓库根目录执行，先将 `PROBE_DEPS` 指向现有隔离依赖目录，将 `PROBE_PYTHON` 指向已激活的 Python 虚拟环境解释器。Python 操作遵循该虚拟环境的使用说明，不使用系统 Python 或全局安装。

```bash
mkdir -p "$PROBE_DEPS/classes"
javac -d "$PROBE_DEPS/classes" -cp "$PROBE_DEPS/jcc.jar:$PROBE_DEPS/hbase-shaded-client.jar" scripts/enterprise-auth-client-probes/Db2Probe.java scripts/enterprise-auth-client-probes/HBaseProbe.java
dotnet build scripts/enterprise-auth-client-probes/EnterpriseAuthProbe.csproj
dotnet run --no-build --project scripts/enterprise-auth-client-probes/EnterpriseAuthProbe.csproj -- db2 java -cp "$PROBE_DEPS/jcc.jar:$PROBE_DEPS/classes" Db2Probe '{port}'
dotnet run --no-build --project scripts/enterprise-auth-client-probes/EnterpriseAuthProbe.csproj -- db2 java -cp "$PROBE_DEPS/jcc.jar:$PROBE_DEPS/classes" Db2Probe '{port}' 3
dotnet run --no-build --project scripts/enterprise-auth-client-probes/EnterpriseAuthProbe.csproj -- oracle "$PROBE_PYTHON" scripts/enterprise-auth-client-probes/oracle_probe.py '{port}'
dotnet run --no-build --project scripts/enterprise-auth-client-probes/EnterpriseAuthProbe.csproj -- hbase java -cp "$PROBE_DEPS/hbase-shaded-client.jar:$PROBE_DEPS/slf4j-api.jar:$PROBE_DEPS/slf4j-nop.jar:$PROBE_DEPS/classes" HBaseProbe '{port}'
```

预期：四项均退出 0 并输出 `PASS`。Db2 默认机制 9/AES 及机制 3 均可取得样本密码；线协议失败码为 `SECCHKCD_0F`，JCC 映射为 `-4214 / SQLSTATE 28000`，不要把 CLI 的 SQL30082N 表述套用到 JCC。Oracle 返回 ORA-01017，HBase 返回原生 InvalidToken；后二者密码为空、保存实际挑战响应。

范围限制：Oracle 此次验证普通 TCP/Thin 密码路径，未验证 JDBC/OCI、TCPS 或 Native Network Encryption；Db2 验证 LUW JCC 默认 AES 与明文机制，未验证 CLP、z/OS 或 TLS；HBase 验证原生 delegation-token SASL，不覆盖 KDC/Kerberos 互认证或完整集群发现。SIMPLE 拒绝另有 RPC protobuf 回归测试。认证失败不需要部署数据库、文件系统或 HBase 集群。
