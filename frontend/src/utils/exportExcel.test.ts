import { strFromU8, unzipSync } from 'fflate';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { type ExcelCell, exportExcel } from './exportExcel';

afterEach(() => {
  vi.restoreAllMocks();
  vi.useRealTimers();
});

describe('exportExcel', () => {
  it('downloads an XLSX with literal input, typed cells, and valid XML', async () => {
    vi.useFakeTimers();
    let blob: Blob | undefined;
    vi.spyOn(URL, 'createObjectURL').mockImplementation((value) => {
      if (value instanceof Blob) blob = value;
      return 'blob:workbook';
    });
    const revoke = vi
      .spyOn(URL, 'revokeObjectURL')
      .mockImplementation(() => {});
    const click = vi
      .spyOn(HTMLAnchorElement.prototype, 'click')
      .mockImplementation(function (this: HTMLAnchorElement) {
        expect(this.download).toBe('威胁事件.xlsx');
        expect(this.href).toBe('blob:workbook');
        expect(this.isConnected).toBe(true);
      });
    await exportExcel(
      '威胁事件',
      '事件 & 报告',
      ['账户', '分数', '拦截', '缺失', '证据编号', '名称', '描述'],
      [
        [
          '=1+1 <>&"🧪\u0000\r',
          42,
          false,
          undefined,
          '000000123',
          '_x000D_',
          `${'a'.repeat(32_766)}🧪`,
        ],
      ],
    );

    expect(click).toHaveBeenCalledOnce();
    expect(document.querySelector('a[download]')).toBeNull();
    expect(blob?.type).toBe(
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    );
    if (!blob) throw new Error('Missing workbook download');
    const parts = unzipSync(new Uint8Array(await blob.arrayBuffer()));
    const parse = (name: string) =>
      new DOMParser().parseFromString(
        strFromU8(parts[name]),
        'application/xml',
      );
    expect(
      parse('_rels/.rels')
        .querySelector('Relationship')
        ?.getAttribute('Target'),
    ).toBe('xl/workbook.xml');
    expect(
      parse('xl/workbook.xml').querySelector('sheet')?.getAttribute('name'),
    ).toBe('事件 & 报告');
    const sheet = parse('xl/worksheets/sheet1.xml');
    expect(sheet.querySelector('parsererror, f')).toBeNull();
    expect(sheet.querySelector('c[r="A2"]')?.getAttribute('t')).toBe(
      'inlineStr',
    );
    expect(sheet.querySelector('c[r="A2"] t')?.textContent).toBe(
      '=1+1 <>&"🧪_x0000__x000D_',
    );
    expect(sheet.querySelector('c[r="B2"] v')?.textContent).toBe('42');
    expect(sheet.querySelector('c[r="C2"][t="b"] v')?.textContent).toBe('0');
    expect(sheet.querySelector('c[r="D2"]')).toBeNull();
    expect(sheet.querySelector('c[r="E2"][t="inlineStr"] t')?.textContent).toBe(
      '000000123',
    );
    expect(sheet.querySelector('c[r="F2"] t')?.textContent).toBe(
      '_x005F_x000D_',
    );
    expect(sheet.querySelector('c[r="G2"] t')?.textContent).toBe(
      `${'a'.repeat(32_766)}�`,
    );

    expect(revoke).not.toHaveBeenCalled();
    vi.runAllTimers();
    expect(revoke).toHaveBeenCalledWith('blob:workbook');
  });

  it('adds a second sheet linked to its own rows', async () => {
    vi.useFakeTimers();
    let blob: Blob | undefined;
    vi.spyOn(URL, 'createObjectURL').mockImplementation((value) => {
      if (value instanceof Blob) blob = value;
      return 'blob:workbook';
    });
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});
    await exportExcel(
      '事件',
      '事件',
      ['连接编号'],
      [['conn-1']],
      [
        {
          name: '连接步骤',
          headers: ['连接编号', '序号'],
          rows: [
            ['conn-1', 1],
            ['conn-1', 2],
          ],
        },
      ],
    );

    if (!blob) throw new Error('Missing workbook download');
    const parts = unzipSync(new Uint8Array(await blob.arrayBuffer()));
    expect(strFromU8(parts['xl/workbook.xml'])).toContain(
      '<sheet name="连接步骤" sheetId="2" r:id="rId2"/>',
    );
    expect(strFromU8(parts['xl/_rels/workbook.xml.rels'])).toContain(
      'Target="worksheets/sheet2.xml"',
    );
    expect(strFromU8(parts['[Content_Types].xml'])).toContain(
      'PartName="/xl/worksheets/sheet2.xml"',
    );
    expect(strFromU8(parts['xl/worksheets/sheet2.xml'])).toContain(
      '<c r="B3"><v>2</v></c>',
    );
    vi.runAllTimers();
  });

  it('rejects data exceeding sheet dimensions before downloading', async () => {
    const createUrl = vi.spyOn(URL, 'createObjectURL').mockClear();
    await expect(
      exportExcel(
        'events',
        'Events',
        ['IP'],
        new Array<ExcelCell[]>(1_048_576),
      ),
    ).rejects.toBeInstanceOf(RangeError);
    await expect(
      exportExcel('events', 'Events', [], [new Array<ExcelCell>(16_385)]),
    ).rejects.toBeInstanceOf(RangeError);
    expect(createUrl).not.toHaveBeenCalled();
  });
});
