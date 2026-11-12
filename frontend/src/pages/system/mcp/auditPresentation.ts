const jsonTokens = /"(?:[^"\\]|\\.)*"|[{}[\],:]|[^\s{}[\],:]+/g;

function formatJson(value: string): string | undefined {
  try {
    JSON.parse(value);
  } catch {
    return undefined;
  }

  // 只调整空白和字符串转义，保留长整数和数字的原始写法。
  const tokens = value.match(jsonTokens) ?? [];
  const output: string[] = [];
  let depth = 0;
  const newline = () => `\n${'  '.repeat(depth)}`;
  for (const [index, token] of tokens.entries()) {
    switch (token) {
      case '{':
      case '[':
        if (++depth > 128) return undefined;
        output.push(token);
        if (tokens[index + 1] !== (token === '{' ? '}' : ']')) output.push(newline());
        break;
      case '}':
      case ']':
        depth--;
        if (tokens[index - 1] !== (token === '}' ? '{' : '[')) output.push(newline());
        output.push(token);
        break;
      case ',':
        output.push(',', newline());
        break;
      case ':':
        output.push(': ');
        break;
      default:
        output.push(token.startsWith('"') ? JSON.stringify(JSON.parse(token)) : token);
    }
  }
  return output.join('');
}

function formatSseFrame(frame: string): string {
  const parts = frame.split(/(\r\n|\r|\n)/);
  const data = [];
  for (let index = 0; index < parts.length; index += 2) {
    const match = parts[index].match(/^(\uFEFF)?data(?:: ?([^\r\n]*))?$/u);
    if (match) data.push({ index, bom: match[1] ?? '', value: match[2] ?? '' });
  }

  if (!data.length) return frame;
  const formatted = formatJson(data.map((part) => part.value).join('\n'));
  if (formatted === undefined) return frame;

  // 每行仍使用 data 字段，保持事件分隔符和非 data 行原样。
  const lines = formatted.split('\n');
  for (const [offset, part] of data.entries()) {
    const remaining = offset === data.length - 1 ? lines.slice(offset) : lines.slice(offset, offset + 1);
    const separator = parts[part.index + 1] ?? parts[1] ?? '\n';
    parts[part.index] = part.bom + (remaining.length ? remaining.map((line) => `data: ${line}`).join(separator) : 'data:');
  }
  return parts.join('');
}

export function formatAuditPayload(value: string): string {
  const json = formatJson(value);
  if (json !== undefined) return json;

  return value.split(/((?:\r\n|\r(?!\n)|\n){2})/).map((part, index) => index % 2 === 0 ? formatSseFrame(part) : part).join('');
}
