import { afterEach, expect, it, vi } from 'vitest';
import { exportCsv } from './exportCsv';

afterEach(() => {
  vi.restoreAllMocks();
  vi.useRealTimers();
});

it('downloads UTF-8 CSV with escaped cells and treats formula prefixes as text', async () => {
  vi.useFakeTimers();
  let blob: Blob | undefined;
  vi.spyOn(URL, 'createObjectURL').mockImplementation((value) => {
    if (value instanceof Blob) blob = value;
    return 'blob:csv';
  });
  const revoke = vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => {});
  const click = vi
    .spyOn(HTMLAnchorElement.prototype, 'click')
    .mockImplementation(function (this: HTMLAnchorElement) {
      expect(this.download).toBe('password-book.csv');
      expect(this.isConnected).toBe(true);
    });

  exportCsv('password-book', ['账号', '密码'], [
    ['账号,"引号"', '第一行\n第二行'],
    ['空密码', ''],
    ['  ＝1+2', '=1+1'],
    ['+1', '-2'],
    ['@test', '\tinput'],
    ['计数', 3],
  ]);

  expect(click).toHaveBeenCalledOnce();
  expect(blob?.type).toBe('text/csv;charset=utf-8');
  if (!blob) throw new Error('Missing CSV download');
  const bytes = await blob.arrayBuffer();
  expect(Array.from(new Uint8Array(bytes, 0, 3))).toEqual([0xef, 0xbb, 0xbf]);
  expect(new TextDecoder().decode(bytes)).toBe(
    '"账号","密码"\r\n' +
      '"账号,""引号""","第一行\n第二行"\r\n' +
      '"空密码",""\r\n' +
      '"\'  ＝1+2","\'=1+1"\r\n' +
      '"\'+1","\'-2"\r\n' +
      '"\'@test","\'\tinput"\r\n' +
      '"计数","3"\r\n',
  );
  vi.runAllTimers();
  expect(revoke).toHaveBeenCalledWith('blob:csv');
});
