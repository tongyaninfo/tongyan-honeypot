export function parseCredentialEvidenceFields(content: string): Record<string, unknown> {
  try {
    const value: unknown = JSON.parse(content);
    if (value && typeof value === 'object' && !Array.isArray(value)) return value as Record<string, unknown>;
  } catch {
    // 非结构化的证据仍在原文中保留，不能当作密码字段。
  }
  return {};
}

export function isPasswordMaterial(materialType: string): boolean {
  const normalized = materialType.toLowerCase();
  return normalized === 'plaintext' || normalized === 'decrypted';
}

export function getCapturedPassword(fields: Record<string, unknown>, materialType: string): string | undefined {
  return isPasswordMaterial(materialType) && typeof fields.password === 'string' ? fields.password : undefined;
}
