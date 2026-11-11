export type ExcelCell = string | number | boolean | null | undefined;

export interface ExcelSheet {
  name: string;
  headers: string[];
  rows: ExcelCell[][];
}

const MAX_ROWS = 1_048_576;
const MAX_COLUMNS = 16_384;
export const MAX_EXCEL_CELL_LENGTH = 32_767;
const MIME_TYPE =
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet';
const XML = '<?xml version="1.0" encoding="UTF-8"?>';
const SHEET_NS = 'http://schemas.openxmlformats.org/spreadsheetml/2006/main';
const REL_NS =
  'http://schemas.openxmlformats.org/officeDocument/2006/relationships';
const PACKAGE_REL_NS =
  'http://schemas.openxmlformats.org/package/2006/relationships';

function cleanXml(value: string) {
  return value.replace(
    /[^\t\n\r\u0020-\uD7FF\uE000-\uFFFD\u{10000}-\u{10FFFF}]/gu,
    '\uFFFD',
  );
}

function escapeXml(value: string) {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;');
}

function columnName(index: number) {
  let name = '';
  for (
    let column = index + 1;
    column > 0;
    column = Math.floor((column - 1) / 26)
  ) {
    name = String.fromCharCode(65 + ((column - 1) % 26)) + name;
  }
  return name;
}

function writeCell(value: ExcelCell, ref: string) {
  if (value == null) return '';
  if (typeof value === 'number' && Number.isFinite(value))
    return `<c r="${ref}"><v>${value}</v></c>`;
  if (typeof value === 'boolean')
    return `<c r="${ref}" t="b"><v>${value ? 1 : 0}</v></c>`;

  // 按文本写入采集内容。原本就含有转义序列的字面值先保护，再编码 XML 不支持的控制字符。
  const text = String(value)
    .slice(0, MAX_EXCEL_CELL_LENGTH)
    .replace(/_(?=x[0-9a-fA-F]{4}_)/gi, '_x005F_')
    .replace(
      /[^\t\n\u0020-\uD7FF\uE000-\uFFFD\u{10000}-\u{10FFFF}]/gu,
      (character) => {
        const code = character.charCodeAt(0);
        if (code >= 0xd800 && code <= 0xdfff) return '\uFFFD';
        return `_x${code.toString(16).toUpperCase().padStart(4, '0')}_`;
      },
    );
  return `<c r="${ref}" t="inlineStr"><is><t xml:space="preserve">${escapeXml(text)}</t></is></c>`;
}

function writeRow(values: ExcelCell[], index: number) {
  const row = index + 1;
  const cells = values
    .map((value, column) => writeCell(value, `${columnName(column)}${row}`))
    .join('');
  return `<row r="${row}">${cells}</row>`;
}

function uniqueSheetName(value: string, index: number, used: Set<string>) {
  const base =
    cleanXml(
      value
        .replace(/[[\]:*?/\\\t\n\r]/g, ' ')
        .trim()
        .slice(0, 31),
    ).replace(/^'+|'+$/g, '') || `Sheet${index + 1}`;
  let name = base;
  for (let copy = 2; used.has(name.toLowerCase()); copy++) {
    const suffix = ` (${copy})`;
    name = `${cleanXml(base.slice(0, 31 - suffix.length))}${suffix}`;
  }
  used.add(name.toLowerCase());
  return name;
}

/** 将列表及可选明细生成标准工作簿并通过浏览器下载。 */
export async function exportExcel(
  filename: string,
  sheetName: string,
  headers: string[],
  rows: ExcelCell[][],
  additionalSheets: ExcelSheet[] = [],
): Promise<void> {
  const sheets = [{ name: sheetName, headers, rows }, ...additionalSheets];
  for (const sheet of sheets) {
    if (
      sheet.rows.length >= MAX_ROWS ||
      sheet.headers.length > MAX_COLUMNS ||
      sheet.rows.some((row) => row.length > MAX_COLUMNS)
    ) {
      throw new RangeError(
        'The dataset exceeds the Excel worksheet dimensions.',
      );
    }
  }

  const { strToU8, zipSync } = await import('fflate');
  const usedNames = new Set(['history']);
  const sheetParts = sheets.map((sheet, index) => ({
    sheet,
    name: uniqueSheetName(sheet.name, index, usedNames),
    id: index + 1,
    path: `worksheets/sheet${index + 1}.xml`,
  }));
  const parts: Record<string, string> = {
    '[Content_Types].xml': `${XML}
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
  ${sheetParts.map(({ path }) => `<Override PartName="/xl/${path}" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>`).join('\n  ')}
</Types>`,
    '_rels/.rels': `${XML}
<Relationships xmlns="${PACKAGE_REL_NS}">
  <Relationship Id="rId1" Type="${REL_NS}/officeDocument" Target="xl/workbook.xml"/>
</Relationships>`,
    'xl/workbook.xml': `${XML}
<workbook xmlns="${SHEET_NS}" xmlns:r="${REL_NS}">
  <sheets>${sheetParts.map(({ name, id }) => `<sheet name="${escapeXml(name)}" sheetId="${id}" r:id="rId${id}"/>`).join('')}</sheets>
</workbook>`,
    'xl/_rels/workbook.xml.rels': `${XML}
<Relationships xmlns="${PACKAGE_REL_NS}">
  ${sheetParts.map(({ id, path }) => `<Relationship Id="rId${id}" Type="${REL_NS}/worksheet" Target="${path}"/>`).join('\n  ')}
</Relationships>`,
  };
  for (const { sheet, path } of sheetParts) {
    const sheetRows = sheet.rows
      .map((row, index) => writeRow(row, index + 1))
      .join('');
    parts[`xl/${path}`] = `${XML}
<worksheet xmlns="${SHEET_NS}">
  <sheetData>${writeRow(sheet.headers, 0)}${sheetRows}</sheetData>
</worksheet>`;
  }
  const archive = zipSync(
    Object.fromEntries(
      Object.entries(parts).map(([path, xml]) => [path, strToU8(xml)]),
    ),
    { level: 1 },
  );
  const anchor = document.createElement('a');
  anchor.download = `${
    cleanXml(filename)
      .replace(/[<>:"/\\|?*\t\n\r]/g, '-')
      .trim() || 'export'
  }.xlsx`;
  const url = URL.createObjectURL(new Blob([archive], { type: MIME_TYPE }));
  anchor.href = url;
  try {
    document.body.append(anchor);
    anchor.click();
  } finally {
    anchor.remove();
    // 延迟到点击处理完成后释放 URL，给浏览器读取 Blob 的机会。
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
}
