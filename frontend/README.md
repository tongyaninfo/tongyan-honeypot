# Honeypot 管理台

本目录基于 Ant Design Pro 6.0.3 初始化，技术栈为 React 19、Umi Max 4、Ant Design 6、ProComponents 3 和 TypeScript。模板演示代码保留为脚手架，业务导航由 `config/routes.ts` 管理。

## 命令

```bash
npm ci
npm start       # 开发模式，带模板 mock
npm run lint
npm test
npm run build
```

开发时 `/api` 请求代理到 `http://localhost:5080`。生产环境通过 `HONEYPOT_API_BASE_URL` 或同源反向代理配置 API 地址；不要在前端写入凭据。

部署域名需要在部署方案确认后单独配置，模板演示资源不会自动成为生产域名或品牌配置。

## 业务页面

- `/overview`：服务实例、监听器、事件和威胁 IP 统计；
- `/services`：服务实例和多端口草稿配置；
- `/sensors`：监听器状态、绑定端口、活动连接和错误数；
- `/events`：连接、认证失败、协议异常和会话事件查询；
- `/threats`：按来源 IP 聚合的风险档案；
- `/credentials`：认证证据摘要，原始材料不在普通列表展示。
- `/system/ip-location`：管理员配置通研 IP 适配器的开关、协议、主机、端口、数据库及超时，来源为 `ip.tongyaninfo.com`。
- `/reports`：今日、本周、本月或自定义区间运行报告，显示采集覆盖、趋势、协议/来源等排行及进程资源；管理员可发送报告和查看历史快照。
- `/system/notifications`：管理员配置 SMTP、测试收件人、频率限制及日报/周报/月报订阅；通知初始关闭，SSL/TLS 默认勾选。
- `/system/mail-records`：管理员筛选邮件任务、查看正文和尝试记录，并按服务端规则重试失败或结果不确定的邮件。

运行总览、威胁事件、威胁清单和认证证据的来源 IP 使用统一组件，上行显示地址、下行异步补齐归属地。解析默认关闭；开启后合批访问独立解析接口，后台队列处理外部请求，列表加载不等待归属地查询。内网/保留地址和 CIDR 在服务端本地识别。

业务请求集中在 `src/services/honeypot/`；报告和通知分别使用 `reports.ts`、`notifications.ts`，其余页面沿用 `api.ts`。接口不可用时显示明确的空态或降级提示，不使用模板远程演示 API。

报告日期按 `Asia/Shanghai` 展示，趋势缺失值会断开，不能将未采集时段显示为零。CPU/内存明确标注为进程资源；采样正常比例不等于服务可用率。邮件正文使用隔离预览，授权码不回显、不进入浏览器持久存储。此版本只实现报告通知，不含登录、封禁、解封事件通知。验证与未部署边界见[报告邮件通知实施方案](../docs/spec/报告邮件通知实施方案.md)。
