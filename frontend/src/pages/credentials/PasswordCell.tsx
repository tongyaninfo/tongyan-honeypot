import { Typography } from 'antd';
import { useEffect, useState } from 'react';
import { getCredentialEvidence } from '@/services/honeypot/api';
import { getCapturedPassword, parseCredentialEvidenceFields } from '@/utils/credentialEvidence';

export default function PasswordCell({ artifactId }: { artifactId: string }) {
  const [password, setPassword] = useState<string>();

  useEffect(() => {
    const controller = new AbortController();
    let expirationTimer: ReturnType<typeof setTimeout> | undefined;
    // 仅管理员当前页的密码行挂载，原文读取继续走服务端鉴权与审计。
    void getCredentialEvidence(artifactId, { signal: controller.signal })
      .then(({ success, data }) => {
        if (controller.signal.aborted || !success || data?.summary.credentialArtifactId !== artifactId) return;
        const value = getCapturedPassword(parseCredentialEvidenceFields(data.content), data.summary.materialType);
        if (!value) return;

        const expiresAt = Date.parse(data.summary.retentionUntilUtc ?? '');
        if (expiresAt <= Date.now()) return;
        setPassword(value);
        if (Number.isFinite(expiresAt)) {
          const clearAtExpiry = () => {
            const remaining = expiresAt - Date.now();
            if (remaining <= 0) setPassword(undefined);
            else expirationTimer = setTimeout(clearAtExpiry, Math.min(remaining, 2_147_483_647));
          };
          clearAtExpiry();
        }
      })
      .catch(() => {
        // 请求失败或证据不可读时保持空白。
      });

    return () => {
      controller.abort();
      clearTimeout(expirationTimer);
    };
  }, [artifactId]);

  return password ? (
    <Typography.Text code style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{password}</Typography.Text>
  ) : null;
}
