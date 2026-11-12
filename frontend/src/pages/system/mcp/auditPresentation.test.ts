import { expect, it } from 'vitest';
import { formatAuditPayload } from './auditPresentation';

it('formats audit JSON with decoded Chinese while preserving numeric literals', () => {
  const raw = String.raw`{"message":"\u8C03\u7528\u6210\u529F","id":9007199254740993,"elapsed":1e-6}`;
  expect(formatAuditPayload(raw)).toBe([
    '{', '  "message": "调用成功",', '  "id": 9007199254740993,', '  "elapsed": 1e-6', '}',
  ].join('\n'));
});

it('formats valid SSE data and preserves line endings, metadata and non-JSON frames', () => {
  const lines = [
    'event: message', 'id: 23', 'data: {', ': comment', String.raw`data: "message":"\u6210\u529F"}`, '',
    'event: notice', 'data: unchanged', '', '',
  ];
  const pretty = [
    'event: message', 'id: 23', 'data: {', ': comment', 'data:   "message": "成功"', 'data: }', '',
    'event: notice', 'data: unchanged', '', '',
  ];
  expect(formatAuditPayload(lines.join('\r\n'))).toBe(pretty.join('\r\n'));
});
