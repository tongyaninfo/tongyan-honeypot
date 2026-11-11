# 验证脚本

脚本必须可重复、默认只读或只写隔离目录，不读取无关密钥，不执行 Git 操作。后续可在此增加：

- `verify-backend`：编译、单测和 API 合同检查；
- `verify-frontend`：lint、test、build；
- `replay-events`：使用脱敏样本离线回放规则；
- `check-docs`：检查文档链接、路径和状态描述。

- [企业数据库原生客户端回环验收](enterprise-auth-client-probes/README.md)：Oracle、Db2、HBase 标准认证失败与证据关联检查。
