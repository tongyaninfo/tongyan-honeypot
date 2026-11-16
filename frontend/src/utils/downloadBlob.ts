export function downloadBlob(filename: string, blob: Blob) {
  const anchor = document.createElement('a');
  const url = URL.createObjectURL(blob);
  anchor.download = filename;
  anchor.href = url;
  try {
    document.body.append(anchor);
    anchor.click();
  } finally {
    anchor.remove();
    // 给浏览器读取文件的机会，随后释放包含导出内容的 URL。
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
}
