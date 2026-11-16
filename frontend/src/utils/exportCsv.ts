import { downloadBlob } from './downloadBlob';

function csvCell(value: string | number) {
  const text = String(value);
  // 带引号的 CSV 单元格仍会被表格软件当作公式，需要另外按文本转义。
  const escapedText =
    /^[\t\r\n]/u.test(text) || /^[=+@＝＋－＠-]/u.test(text.trimStart())
      ? `'${text}`
      : text;
  return `"${escapedText.replaceAll('"', '""')}"`;
}

export function exportCsv(
  filename: string,
  headers: string[],
  rows: (string | number)[][],
) {
  const lines = [headers, ...rows].map(
    (row) => `${row.map(csvCell).join(',')}\r\n`,
  );
  downloadBlob(
    `${filename}.csv`,
    new Blob(['\uFEFF', ...lines], { type: 'text/csv;charset=utf-8' }),
  );
}
