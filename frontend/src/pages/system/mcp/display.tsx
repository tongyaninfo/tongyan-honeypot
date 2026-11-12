import { CopyOutlined } from '@ant-design/icons';
import { Button, Empty, Flex, Typography } from 'antd';
import { useEffect, useMemo, useRef, useState } from 'react';
import type { McpAccess, McpCallResult, McpKeyStatus } from '@/services/honeypot/mcp';
import { formatAuditPayload } from './auditPresentation';

const dateTime = new Intl.DateTimeFormat('zh-CN', {
  timeZone: 'Asia/Shanghai',
  year: 'numeric',
  month: '2-digit',
  day: '2-digit',
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
  hourCycle: 'h23',
});

export function formatMcpTime(value?: string | null): string {
  return value && Number.isFinite(Date.parse(value)) ? dateTime.format(new Date(value)) : '—';
}

/** 表单以北京时间输入，避免浏览器系统时区改变过期或筛选时刻。 */
export function beijingTimeToUtc(value?: string): string | undefined {
  if (!value || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(value)) return undefined;
  const instant = Date.parse(`${value}:00+08:00`);
  if (!Number.isFinite(instant) || new Date(instant + 8 * 3600000).toISOString().slice(0, 16) !== value) return undefined;
  return new Date(instant).toISOString();
}

export const accessLabels: Record<McpAccess, string> = { ReadOnly: '只读', ReadWrite: '读写' };

export const keyStates: Record<McpKeyStatus, { label: string; color: string }> = {
  Active: { label: '有效', color: 'success' },
  Expired: { label: '已过期', color: 'warning' },
  Revoked: { label: '已吊销', color: 'default' },
};

export const callResults: Record<McpCallResult, { label: string; color: string }> = {
  Pending: { label: '处理中', color: 'processing' },
  Success: { label: '成功', color: 'success' },
  ToolError: { label: '工具失败', color: 'error' },
  ProtocolError: { label: '协议错误', color: 'error' },
  Denied: { label: '拒绝', color: 'warning' },
  RateLimited: { label: '限流', color: 'warning' },
  Unavailable: { label: '不可用', color: 'error' },
  Unknown: { label: '结果未知', color: 'default' },
};

export const mcpBaseUrl = () => typeof window === 'undefined' ? '' : window.location.origin;

export function connectionInstructions(origin: string): string {
  return [
    '请在当前客户端注册远程 MCP 服务 tongyan-honeypot。',
    `Base URL: ${origin}`,
    `MCP Endpoint: ${origin}/mcp`,
    'Transport: Streamable HTTP',
    `Authorization: Bearer \${HONEYPOT_MCP_API_KEY}`,
    '',
    '从客户端安全配置读取 HONEYPOT_MCP_API_KEY，并用该值设置 Bearer 请求头。请勿打印密钥。',
    '按客户端支持的格式保存 MCP 配置，连接后运行 tools/list 验证已授权的工具。',
  ].join('\n');
}

export async function writeMcpClipboard(value: string): Promise<boolean> {
  try {
    if (!navigator.clipboard) return false;
    await navigator.clipboard.writeText(value);
    return true;
  } catch {
    return false;
  }
}

function selectCopyText(content: HTMLPreElement | null): string {
  const selection = window.getSelection();
  if (!selection || !content) return '请手动选中文本并复制';
  const range = document.createRange();
  range.selectNodeContents(content);
  selection.removeAllRanges();
  selection.addRange(range);
  return '已选中文本，请手动复制';
}

export function McpCopyBlock({ label, value, emptyText, formatAudit = false }: { label: string; value?: string | null; emptyText?: string | null; formatAudit?: boolean }) {
  const content = useRef<HTMLPreElement>(null);
  const selectRawAfterRender = useRef(false);
  const [feedback, setFeedback] = useState('');
  const [showRaw, setShowRaw] = useState(false);
  const formatted = useMemo(() => formatAudit && value != null ? formatAuditPayload(value) : value, [formatAudit, value]);
  const canToggle = formatted !== value;

  useEffect(() => {
    if (!showRaw || !selectRawAfterRender.current) return;
    selectRawAfterRender.current = false;
    setFeedback(selectCopyText(content.current));
  }, [showRaw]);

  const copy = async () => {
    if (value == null) return;
    if (await writeMcpClipboard(value)) {
      setFeedback('已复制');
      return;
    }
    if (canToggle && !showRaw) {
      selectRawAfterRender.current = true;
      setShowRaw(true);
    } else {
      setFeedback(selectCopyText(content.current));
    }
  };

  if (value == null) return <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={emptyText || `无${label}`} />;

  return (
    <Flex vertical gap={8} className="mcp-copy-panel">
      <Flex justify="space-between" align="center" wrap="wrap" gap={8}>
        <Typography.Text strong>{label}</Typography.Text>
        <Flex align="center" wrap="wrap" gap={8}>
          <Typography.Text type="secondary" role="status">{feedback}</Typography.Text>
          {canToggle && <Button type="text" size="small" onClick={() => { setFeedback(''); setShowRaw((current) => !current); }}>{showRaw ? '格式化显示' : '查看原文'}</Button>}
          <Button size="small" icon={<CopyOutlined aria-hidden />} onClick={copy}>复制{label}</Button>
        </Flex>
      </Flex>
      <pre ref={content} className="mcp-code-block">{showRaw ? value : formatted}</pre>
    </Flex>
  );
}
