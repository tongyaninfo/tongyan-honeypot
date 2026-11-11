import { BarChartOutlined, MailOutlined, ReloadOutlined } from '@ant-design/icons';
import { ConfigProvider as PlotConfigProvider, Line } from '@ant-design/plots';
import { Link, useAccess, useModel } from '@umijs/max';
import { Alert, Button, Card, Col, Empty, Form, Input, Modal, Row, Segmented, Space, Spin, Statistic, Table, Tag, Typography } from 'antd';
import { createStyles } from 'antd-style';
import { type ComponentProps, useEffect, useMemo, useRef, useState } from 'react';
import { getOperationReport, getReportHistory, getReportHistoryDetails, type OperationReport, type ReportBreakdown, type ReportHistoryItem, type ReportPeriodKind, type ReportQuery, sendOperationReport } from '@/services/honeypot/reports';
import { formatCoveragePercent, formatReportAxisTime, formatReportCount, formatReportTime, formatUncoveredDuration, parseRecipients, recipientRules, reportApiError, reportDateRange } from '@/utils/reportFormat';
import { resolveTheme } from '@/utils/theme';

const useStyles = createStyles(({ token, css }) => ({
  // 图表和带横向滚动的表格不能通过 min-content 反向撑宽整页网格。
  page: css`display: grid; grid-template-columns: minmax(0, 1fr); gap: 20px; width: 100%; min-width: 0; max-width: 100%; box-sizing: border-box; > * { min-width: 0; } .ant-card, .ant-card-body, .ant-table-wrapper { min-width: 0; }`,
  hero: css`min-width: 0; box-sizing: border-box; padding: 28px; border: 1px solid ${token.colorBorderSecondary}; border-radius: 16px; background: linear-gradient(120deg, ${token.colorPrimaryBg}, ${token.colorBgContainer} 75%); @media(max-width: 520px) { padding: 18px; }`,
  toolbar: css`display: flex; min-width: 0; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 16px; > * { min-width: 0; max-width: 100%; }`,
  metrics: css`display: grid; min-width: 0; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 16px; > * { min-width: 0; } @media(max-width: 1100px) { grid-template-columns: repeat(2, minmax(0, 1fr)); } @media(max-width: 520px) { grid-template-columns: minmax(0, 1fr); }`,
  small: css`color: ${token.colorTextSecondary}; font-size: 12px; margin-top: 10px;`,
}));

const number = formatReportCount;
const percent = (value?: number | null) => value == null ? '暂不可用' : `${value.toFixed(1)}%`;
const memory = (value?: number | null) => value == null ? '暂不可用' : `${(value / 1024 / 1024).toFixed(1)} MiB`;
const disk = (value?: number | null) => value == null ? '暂不可用' : `${(value / 1024 / 1024 / 1024).toFixed(1)} GiB`;
const change = (value?: number | null) => value == null ? '暂无可比数据' : `较上期同期 ${value > 0 ? '+' : ''}${value.toFixed(1)}%`;
const coverageLabels: Record<string, string> = { complete: '采集覆盖完整', partial: '统计区间覆盖不完整', unknown: '采集覆盖未知' };
const periodLabels: Record<string, string> = { day: '今日日报', week: '本周周报', month: '本月月报', custom: '自定义报告' };

export function ResponsiveTrendLine(props: ComponentProps<typeof Line>) {
  const container = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(0);

  useEffect(() => {
    if (!container.current) return;
    // G2 的 autoFit 只监听窗口缩放；父容器初次布局收缩也必须同步重绘画布。
    const observer = new ResizeObserver(([entry]) => setWidth(Math.max(0, Math.floor(entry.contentRect.width))));
    observer.observe(container.current);
    return () => observer.disconnect();
  }, []);

  return <div ref={container} style={{ width: '100%', minWidth: 0, height: 280 }}>{width > 0 && <Line {...props} width={width} autoFit={false} />}</div>;
}

function BreakdownCard({ title, name, data, kind = 'general' }: { title: string; name: string; data: ReportBreakdown[]; kind?: 'general' | 'source' | 'account' }) {
  const columns = [
    { title: name, dataIndex: 'key', ellipsis: true, render: (key: string) => kind === 'source' ? <Typography.Text copyable>{key || '未知'}</Typography.Text> : key || '未知' },
    ...(kind === 'account' ? [] : [{ title: '连接', dataIndex: 'connections', width: 72, render: number }]),
    { title: '认证失败', dataIndex: 'authenticationFailures', width: 92, render: number },
    { title: '来源 IP', dataIndex: 'sourceIps', width: 82, render: number },
  ];
  return <Card title={title} extra={<Typography.Text type="secondary">Top 10</Typography.Text>} style={{ height: '100%' }} styles={{ body: { padding: '8px 16px' } }}>
    <Table size="small" rowKey="key" dataSource={data} columns={columns} pagination={false} scroll={{ x: 360 }} locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="本期暂无已记录数据" /> }} />
  </Card>;
}

export default function ReportsPage() {
  const access = useAccess();
  return <ReportsContent canAdmin={access.canAdmin} />;
}

function ReportsContent({ canAdmin }: { canAdmin: boolean }) {
  const { styles } = useStyles();
  const { initialState } = useModel('@@initialState');
  const dark = resolveTheme(initialState?.themeMode ?? 'light') === 'realDark';
  const [selection, setSelection] = useState<ReportPeriodKind>('day');
  const [query, setQuery] = useState<ReportQuery>({ period: 'day' });
  const [fromDate, setFromDate] = useState('');
  const [toDate, setToDate] = useState('');
  const [report, setReport] = useState<OperationReport>();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [refresh, setRefresh] = useState(0);
  const [sendOpen, setSendOpen] = useState(false);
  const [sending, setSending] = useState(false);
  const [feedback, setFeedback] = useState<{ type: 'success' | 'error'; text: string }>();
  const [sendForm] = Form.useForm<{ recipients: string }>();
  const [taskIds, setTaskIds] = useState<string[]>([]);
  const [historyId, setHistoryId] = useState<string>();
  const [history, setHistory] = useState<ReportHistoryItem[]>([]);
  const [historyPage, setHistoryPage] = useState(1);
  const [historyTotal, setHistoryTotal] = useState(0);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [historyError, setHistoryError] = useState(false);
  const todayDate = new Date(Date.now() + 8 * 3_600_000).toISOString().slice(0, 10);
  const sendTitle = query.period === 'custom' ? '发送当前区间报告' : '生成并发送最新报告';

  useEffect(() => {
    const controller = new AbortController();
    let active = true;
    setLoading(true); setError(''); setReport(undefined);
    void (canAdmin && historyId ? getReportHistoryDetails(historyId, controller.signal) : getOperationReport(query, controller.signal)).then((response) => {
      if (!active) return;
      if (!response.success || !response.data) throw new Error('Report unavailable');
      setReport(response.data);
    }).catch(() => { if (active) setError('运行报告暂不可用，请检查管理员权限或稍后重试。'); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; controller.abort(); };
  }, [query, refresh, historyId, canAdmin]);

  useEffect(() => {
    if (!canAdmin) { setHistory([]); setHistoryTotal(0); setHistoryLoading(false); return; }
    const controller = new AbortController(); let active = true;
    setHistoryLoading(true); setHistoryError(false);
    void getReportHistory(historyPage, 10, controller.signal).then((response) => {
      if (!active) return;
      if (!response.success || !response.data) throw new Error('History unavailable');
      setHistory(response.data.items); setHistoryTotal(response.data.total);
    }).catch(() => { if (active) { setHistoryError(true); setHistory([]); } }).finally(() => { if (active) setHistoryLoading(false); });
    return () => { active = false; controller.abort(); };
  }, [historyPage, refresh, canAdmin]);

  const trend = useMemo(() => (report?.trend ?? []).flatMap((point) => [
    { time: point.startAtUtc, displayTime: formatReportTime(point.startAtUtc), series: '连接', count: point.connections, coverage: coverageLabels[point.coverageStatus] ?? '覆盖未知' },
    { time: point.startAtUtc, displayTime: formatReportTime(point.startAtUtc), series: '认证失败', count: point.authenticationFailures, coverage: coverageLabels[point.coverageStatus] ?? '覆盖未知' },
    { time: point.startAtUtc, displayTime: formatReportTime(point.startAtUtc), series: '协议异常', count: point.protocolViolations, coverage: coverageLabels[point.coverageStatus] ?? '覆盖未知' },
  ]), [report]);
  const trendCrossesYear = report ? formatReportTime(report.period.startAtUtc).slice(0, 4) !== formatReportTime(new Date(Date.parse(report.period.endAtUtc) - 1).toISOString()).slice(0, 4) : false;

  const applyCustom = () => {
    const range = reportDateRange(fromDate, toDate, new Date(Date.now()));
    if (!range) { setFeedback({ type: 'error', text: '请选择有效的起止日期：结束日期不能早于开始日期，日期不能晚于今天。' }); return; }
    if (Date.parse(range.toUtc) - Date.parse(range.fromUtc) > 366 * 86_400_000) { setFeedback({ type: 'error', text: '自定义报告区间最长为 366 天。' }); return; }
    setFeedback(undefined);
    setHistoryId(undefined);
    setQuery({ period: 'custom', startAtUtc: range.fromUtc, endAtUtc: range.toUtc });
  };
  const send = async ({ recipients }: { recipients: string }) => {
    if (!report || !canAdmin) return;
    setSending(true);
    try {
      // 自然周期保留原始类型和上期口径；自定义查询复用查询时确定的边界。
      const response = await sendOperationReport({ ...query, recipients: parseRecipients(recipients) });
      if (!response.success) throw response;
      setSendOpen(false); sendForm.resetFields();
      setTaskIds(response.data.deliveryIds);
      setFeedback({ type: 'success', text: '报告邮件已加入发送队列，请到邮件记录查看结果。' });
    } catch (error) { setFeedback({ type: 'error', text: reportApiError(error, '报告邮件未能加入队列，请检查邮件配置、收件人和发送频率限制。') }); }
    finally { setSending(false); }
  };

  return <div className={styles.page}>
    <div className={styles.hero}>
      <div className={styles.toolbar}>
        <div><Space><BarChartOutlined style={{ fontSize: 24 }} /><Typography.Title level={3} style={{ margin: 0 }}>蜜罐运行报告</Typography.Title></Space>
          <Typography.Paragraph type="secondary" style={{ marginTop: 10, marginBottom: 0 }}>连接与认证活动、风险信号和服务运行，一份报告完整掌握。</Typography.Paragraph></div>
        <Space wrap><Button icon={<ReloadOutlined />} loading={loading} onClick={() => setRefresh((value) => value + 1)}>刷新报告</Button>{canAdmin && <Button type="primary" icon={<MailOutlined aria-hidden />} disabled={!report || loading || Boolean(historyId)} onClick={() => setSendOpen(true)}>{sendTitle}</Button>}</Space>
      </div>
      <div className={styles.toolbar} style={{ marginTop: 24 }}>
        <Segmented value={selection} options={[{ label: '今日', value: 'day' }, { label: '本周', value: 'week' }, { label: '本月', value: 'month' }, { label: '自定义', value: 'custom' }]} onChange={(value) => { const period = value as ReportPeriodKind; setSelection(period); setHistoryId(undefined); if (period !== 'custom') setQuery({ period }); }} />
        <Typography.Text type="secondary">Asia/Shanghai · 自然周从周一开始</Typography.Text>
      </div>
      {selection === 'custom' && <><Space wrap style={{ marginTop: 16 }}><Input aria-label="开始日期" type="date" max={todayDate} value={fromDate} onChange={(event) => setFromDate(event.target.value)} /><Typography.Text>至</Typography.Text><Input aria-label="结束日期" type="date" max={todayDate} value={toDate} onChange={(event) => setToDate(event.target.value)} /><Button onClick={applyCustom}>查询区间</Button></Space><Typography.Paragraph type="secondary" style={{ marginTop: 10, marginBottom: 0 }}>包含今天时，统计截至点击查询的时刻；历史日期按完整自然日统计。</Typography.Paragraph></>}
    </div>
    {feedback && <Alert type={feedback.type} showIcon title={feedback.text} closable onClose={() => setFeedback(undefined)} />}
    {taskIds.length > 0 && <Alert type="info" title={<Space wrap><span>任务：{taskIds.join('、')}</span><Link to={`/system/mail-records?status=all&id=${encodeURIComponent(taskIds[0])}`}>查看邮件记录</Link></Space>} />}
    {canAdmin && historyId && <Alert type="info" showIcon title="正在查看已生成报告的历史快照" description="历史快照保留生成时的数据和统计范围。邮件重新发送请使用邮件记录中的原始邮件。" action={<Button onClick={() => setHistoryId(undefined)}>返回当前报告</Button>} />}
    {error && <Alert type="error" showIcon title={error} action={<Button size="small" onClick={() => setRefresh((value) => value + 1)}>重试</Button>} />}
    {loading && <Card><div style={{ padding: 80, textAlign: 'center' }}><Spin description="正在汇总运行数据" /></div></Card>}
    {report && <>
      <div className={styles.toolbar}><Space wrap><Typography.Title level={4} style={{ margin: 0 }}>{periodLabels[report.period.kind] ?? '运行报告'}</Typography.Title>{report.period.isCurrentPeriod && <Tag color="processing">截至当前</Tag>}<Tag color={report.coverage.status === 'complete' ? 'success' : 'warning'}>{coverageLabels[report.coverage.status] ?? '覆盖状态未知'}</Tag></Space><Typography.Text type="secondary">生成于 {formatReportTime(report.generatedAtUtc)}</Typography.Text></div>
      <Typography.Text type="secondary">统计范围：{formatReportTime(report.period.startAtUtc)} 至 {formatReportTime(report.period.endAtUtc)}（结束时刻不包含在内）</Typography.Text>
      {report.coverage.status !== 'complete' && <Alert showIcon type="warning" title={`采集覆盖 ${formatCoveragePercent(report.coverage.coveragePercent, report.coverage.status)}，以下数值仅代表已记录数据`} description={`未覆盖时间：${formatUncoveredDuration(report.coverage.unknownSeconds)}。未知时段不能解释为零事件；没有采样的运行指标显示“暂不可用”。`} />}
      <div className={styles.metrics}>
        {[
          ['接收连接', report.totals.acceptedConnections, change(report.comparison.connectionChangePercent)],
          ['独立来源 IP', report.totals.uniqueSourceIps, change(report.comparison.sourceIpChangePercent)],
          ['认证失败', report.totals.authenticationFailures, change(report.comparison.authenticationFailureChangePercent)],
          ['协议异常', report.totals.protocolViolations, '协议格式、交互或约束异常'],
          ['新增来源 IP', report.totals.newSourceIps, '首次被本系统观测发生在本期'],
          ['认证尝试', report.totals.authenticationAttempts, '按尝试计数，一条连接可多次认证'],
          ['认证证据', report.totals.evidenceCount, '仅统计数量，不展示原始认证材料'],
          ['截断事件', report.totals.truncatedEvents, '达到资源或采集上限的事件'],
        ].map(([title, value, hint]) => <Card key={String(title)}><Statistic title={title} value={number(value as number | null)} /><div className={styles.small}>{hint}</div></Card>)}
      </div>
      <Card title="连接与认证趋势" extra={<Typography.Text type="secondary">{report.period.granularity === 'hour' ? '按小时' : '按天'} · 已记录事件</Typography.Text>}>
        {report.coverage.status === 'unknown' && !report.coverage.hasObservedEvents ? <Empty description="暂无可用观测，不能推断本期没有活动" /> : <PlotConfigProvider common={{ theme: dark ? 'dark' : 'light' }}><ResponsiveTrendLine height={280} data={trend} xField="time" yField="count" colorField="series" connectNulls={false} scale={{ color: { range: ['#1677ff', '#f26b6b', '#f5a623'] } }} axis={{ x: { title: false, labelAutoHide: true, labelAutoRotate: false, labelFormatter: (value: string) => formatReportAxisTime(value, report.period.granularity, trendCrossesYear) }, y: { title: false } }} legend={{ color: { position: 'top' } }} tooltip={{ title: (datum: { displayTime: string }) => datum.displayTime, items: [{ field: 'series', name: '指标' }, { field: 'count', name: '数量' }, { field: 'coverage', name: '采集覆盖' }] }} /></PlotConfigProvider>}
        <Typography.Text type="secondary">未覆盖且无记录的时段显示为断点；部分覆盖时仅展示已记录数量。</Typography.Text>
      </Card>
      <Row gutter={[20, 20]}>
        <Col xs={24} xl={12}><BreakdownCard title="协议活动" name="协议" data={report.protocols} /></Col>
        <Col xs={24} xl={12}><BreakdownCard title="目标端口" name="端口" data={report.ports} /></Col>
        <Col xs={24} xl={12}><BreakdownCard title="主要来源" name="来源 IP" data={report.sources} kind="source" /></Col>
        <Col xs={24} xl={12}><BreakdownCard title="来源地区" name="地区" data={report.regions} /></Col>
        <Col xs={24} xl={12}><BreakdownCard title="认证方式" name="方式" data={report.authenticationMethods} kind="account" /></Col>
        <Col xs={24} xl={12}><BreakdownCard title="尝试登录的账户" name="账户" data={report.usernames} kind="account" /></Col>
        <Col xs={24} xl={12}><Card title="事件风险增量分布与证据摘要" style={{ height: '100%' }}><Typography.Paragraph type="secondary">风险按事件风险增量分组，不能视为已执行封禁。凭据仅展示材料分类和计数。</Typography.Paragraph><Table rowKey="key" size="small" pagination={false} dataSource={[...report.riskSignals.map((item) => ({ ...item, key: `风险 · ${item.key}` })), ...report.evidence.map((item) => ({ ...item, key: `证据 · ${item.key}` }))]} columns={[{ title: '分类', dataIndex: 'key' }, { title: '事件', dataIndex: 'events', render: number }, { title: '来源 IP', dataIndex: 'sourceIps', render: number }]} locale={{ emptyText: '本期暂无已记录数据' }} /></Card></Col>
        <Col xs={24} xl={12}><Card title="会话与邮件发送" style={{ height: '100%' }}><Row gutter={[20, 24]}>{[
          ['已关闭会话', number(report.totals.sessionClosed)], ['事件总数', number(report.totals.eventCount)],
          ['SMTP 已受理', number(report.mailSummary?.accepted)], ['发送失败', number(report.mailSummary?.failed)],
          ['排队中', number(report.mailSummary?.pending)], ['发送中', number(report.mailSummary?.sending)],
          ['等待重试', number(report.mailSummary?.retrying)], ['发送结果未知', number(report.mailSummary?.unknown)],
        ].map(([title, value]) => <Col key={title} span={12}><Statistic title={title} value={value} /></Col>)}</Row></Card></Col>
      </Row>
      <Card title="运行与资源采样" extra={<Tag>{number(report.runtime.sampleCount)} 个采样点</Tag>}>
        <Row gutter={[24, 24]}>{[
          ['平均进程 CPU', percent(report.runtime.averageProcessCpuPercent)], ['峰值进程 CPU', percent(report.runtime.peakProcessCpuPercent)],
          ['平均进程内存', memory(report.runtime.averageProcessMemoryBytes)], ['峰值进程内存', memory(report.runtime.peakProcessMemoryBytes)],
          ['峰值活动连接', number(report.runtime.peakActiveConnections)], ['平均运行监听器', report.runtime.averageRunningListeners == null ? '暂不可用' : report.runtime.averageRunningListeners.toFixed(1)],
          ['峰值故障监听器', number(report.runtime.peakFailedListeners)], ['采样正常比例', percent(report.runtime.allListenersRunningPercent)],
          ['最后采样磁盘可用空间', disk(report.runtime.lastDataDiskFreeBytes)], ['最低磁盘可用空间', disk(report.runtime.minimumDataDiskFreeBytes)],
        ].map(([title, value]) => <Col key={title} xs={12} xl={6}><Statistic title={title} value={value} /></Col>)}</Row>
        <Typography.Paragraph type="secondary" style={{ marginTop: 24, marginBottom: 0 }}>CPU 和内存为蜜罐进程采样值。监听运行占比仅覆盖已采样时刻，不代表完整服务可用率。最后采样：{formatReportTime(report.runtime.lastSampleAtUtc)}。</Typography.Paragraph>
      </Card>
      <Card title="统计口径与数据说明" size="small"><Space orientation="vertical" size={8} style={{ display: 'flex' }}><Typography.Text type="secondary">比较区间：{formatReportTime(report.comparison.startAtUtc)} 至 {formatReportTime(report.comparison.endAtUtc)}；{coverageLabels[report.comparison.coverageStatus] ?? '覆盖未知'}。无法可靠比较时不显示增减比例。</Typography.Text>{report.notes.map((note) => <Typography.Text key={note} type="secondary">{note}</Typography.Text>)}</Space></Card>
    </>}
    {canAdmin && <Card title="已生成报告" extra={<Typography.Text type="secondary">定时与手动发送时保存的快照</Typography.Text>}>
      {historyError && <Alert type="warning" title="报告历史暂不可用" style={{ marginBottom: 16 }} />}
      <Table rowKey="id" loading={historyLoading} dataSource={history} scroll={{ x: 780 }} pagination={{ current: historyPage, pageSize: 10, total: historyTotal, showSizeChanger: false, onChange: setHistoryPage }} columns={[
        { title: '报告', dataIndex: 'title', render: (title: string, item: ReportHistoryItem) => <Button type="link" style={{ padding: 0 }} onClick={() => setHistoryId(item.id)}>{title}</Button> },
        { title: '开始时间', dataIndex: 'startAtUtc', render: formatReportTime }, { title: '结束时间', dataIndex: 'endAtUtc', render: formatReportTime },
        { title: '生成时间', dataIndex: 'generatedAtUtc', render: formatReportTime }, { title: '收件人', dataIndex: 'recipientCount', width: 80 },
      ]} locale={{ emptyText: historyError ? '历史数据不可用' : '暂无已生成报告' }} />
    </Card>}
    <Modal title={sendTitle} open={canAdmin && sendOpen} onCancel={() => !sending && setSendOpen(false)} footer={null} destroyOnHidden>
      <Typography.Paragraph>{query.period === 'custom' ? '按当前已查询的起止时间生成报告，包含今天的区间保持查询时确定的结束时刻。' : '按所选自然日、周或月重新汇总至发送时刻，保留相同的周期和上期比较口径。'}</Typography.Paragraph>
      <Typography.Paragraph type="secondary">使用已保存的邮件服务器配置。任务入队后，可在邮件记录查看 SMTP 服务器是否接受；这不代表收件人已收到。</Typography.Paragraph>
      <Form form={sendForm} layout="vertical" onFinish={send}><Form.Item name="recipients" label="收件人" rules={recipientRules}><Input.TextArea rows={3} placeholder="admin@example.com, security@example.com" /></Form.Item><Button type="primary" htmlType="submit" loading={sending}>加入发送队列</Button></Form>
    </Modal>
  </div>;
}
