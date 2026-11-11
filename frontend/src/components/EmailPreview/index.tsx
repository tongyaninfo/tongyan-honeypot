import { Empty } from 'antd';

/** 邮件内容隔离展示：禁用脚本、表单、同源权限和外部资源，避免取证字段影响管理台。 */
export function isolatedEmailHtml(html: string): string {
  const policy = "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; img-src data:; font-src 'none'; form-action 'none'; base-uri 'none'\">";
  return `${policy}${html}`;
}

export default function EmailPreview({ html, title = '邮件内容预览' }: { html?: string | null; title?: string }) {
  if (!html) return <Empty description="暂无邮件内容" />;
  return <iframe
    title={title}
    sandbox=""
    referrerPolicy="no-referrer"
    srcDoc={isolatedEmailHtml(html)}
    style={{ width: '100%', minHeight: 620, border: '1px solid #e8edf4', borderRadius: 12, background: '#f5f7fb' }}
  />;
}
