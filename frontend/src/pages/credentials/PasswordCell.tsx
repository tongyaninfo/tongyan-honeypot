import { Typography } from 'antd';
import { useEffect, useState } from 'react';
import { getCredentialEvidence } from '@/services/honeypot/api';
import {
  getCapturedPassword,
  parseCredentialEvidenceFields,
} from '@/utils/credentialEvidence';

interface PasswordCellProps {
  artifactId: string;
  emptyPasswordText?: string;
  loadingText?: string;
  unavailableText?: string;
}

export default function PasswordCell({
  artifactId,
  emptyPasswordText,
  loadingText,
  unavailableText,
}: PasswordCellProps) {
  const [read, setRead] = useState<{ artifactId: string; password?: string }>();

  useEffect(() => {
    const controller = new AbortController();
    let expirationTimer: ReturnType<typeof setTimeout> | undefined;
    const markUnavailable = () => {
      if (!controller.signal.aborted) setRead({ artifactId });
    };
    // 仅管理员当前页的密码行挂载，原文读取继续走服务端鉴权与审计。
    void getCredentialEvidence(artifactId, { signal: controller.signal })
      .then(({ success, data }) => {
        if (controller.signal.aborted) return;
        if (!success || data?.summary.credentialArtifactId !== artifactId)
          return markUnavailable();
        const value = getCapturedPassword(
          parseCredentialEvidenceFields(data.content),
          data.summary.materialType,
        );
        if (value === undefined) return markUnavailable();

        const expiresAt = Date.parse(data.summary.retentionUntilUtc ?? '');
        if (expiresAt <= Date.now()) return markUnavailable();
        setRead({ artifactId, password: value });
        if (Number.isFinite(expiresAt)) {
          const clearAtExpiry = () => {
            const remaining = expiresAt - Date.now();
            if (remaining <= 0) markUnavailable();
            else
              expirationTimer = setTimeout(
                clearAtExpiry,
                Math.min(remaining, 2_147_483_647),
              );
          };
          clearAtExpiry();
        }
      })
      .catch(markUnavailable);

    return () => {
      controller.abort();
      clearTimeout(expirationTimer);
    };
  }, [artifactId]);

  const current = read?.artifactId === artifactId ? read : undefined;
  if (current?.password) {
    return (
      <Typography.Text
        code
        style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}
      >
        {current.password}
      </Typography.Text>
    );
  }

  const fallback = !current
    ? loadingText
    : current.password === ''
      ? emptyPasswordText
      : unavailableText;
  return fallback ? (
    <Typography.Text type="secondary">{fallback}</Typography.Text>
  ) : null;
}
