const displayTime = new Intl.DateTimeFormat('zh-CN', {
  timeZone: 'Asia/Shanghai', year: 'numeric', month: '2-digit', day: '2-digit',
  hour: '2-digit', minute: '2-digit', hourCycle: 'h23',
});

export const formatReportTime = (value?: string | null): string => {
  if (!value || !Number.isFinite(Date.parse(value))) return '—';
  return displayTime.format(new Date(value));
};

export const formatReportCount = (value?: number | null): string => value === null || value === undefined
  ? '暂不可用' : new Intl.NumberFormat('zh-CN').format(value);

export function formatUncoveredDuration(seconds: number): string {
  if (seconds < 60) return '少于 1 分钟';
  if (seconds < 3600) return `${Math.ceil(seconds / 60)} 分钟`;
  return `${(seconds / 3600).toFixed(1)} 小时`;
}

export function formatCoveragePercent(value: number, status: string): string {
  return status === 'partial' && value >= 99.95 ? '超过 99.9%' : `${value.toFixed(1)}%`;
}

/** 横轴缩短显示，底层仍使用完整 UTC 时间，避免跨日同名时刻被合并。 */
export function formatReportAxisTime(value: string, granularity: string, includeYear = false): string {
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp)) return '—';
  const local = new Date(timestamp + 8 * 3_600_000).toISOString();
  if (granularity === 'hour') return local.slice(11, 16);
  return includeYear ? local.slice(0, 10) : local.slice(5, 10);
}

export function parseRecipients(value: string): string[] {
  return [...new Set(value.split(/[\s,;，；]+/).map((item) => item.trim()).filter(Boolean))];
}

export const recipientRules = [{
  validator: (_: unknown, value?: string) => {
    const recipients = parseRecipients(value ?? '');
    return recipients.length > 0 && recipients.length <= 20 && recipients.every((item) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(item))
      ? Promise.resolve() : Promise.reject(new Error('请输入有效邮箱地址，多个地址用逗号分隔，最多 20 位收件人'));
  },
}];

/** 仅展示服务端统一业务合同中的中文提示，不把请求对象、堆栈或网络异常原文展示出来。 */
export function reportApiError(error: unknown, fallback: string): string {
  const candidate = error as { success?: boolean; code?: string; message?: string; response?: { data?: { success?: boolean; code?: string; message?: string } } } | null;
  const data = candidate?.response?.data ?? candidate;
  return data?.success === false && typeof data.code === 'string' && typeof data.message === 'string'
    ? data.message.slice(0, 500) : fallback;
}

/** 按北京时间自然日查询；传入 now 时拒绝未来日期，并把今天截到查询时刻。 */
export function reportDateRange(from: string, to: string, now?: Date) {
  const fromTime = Date.parse(`${from}T00:00:00+08:00`);
  const toTime = Date.parse(`${to}T00:00:00+08:00`);
  if (!Number.isFinite(fromTime) || !Number.isFinite(toTime) || fromTime > toTime) return undefined;
  const nowTime = now?.getTime();
  if (nowTime !== undefined && (!Number.isFinite(nowTime) || toTime > nowTime)) return undefined;
  const endTime = Math.min(toTime + 86_400_000, nowTime ?? Infinity);
  if (fromTime >= endTime) return undefined;
  return { fromUtc: new Date(fromTime).toISOString(), toUtc: new Date(endTime).toISOString() };
}
