import { useIntl } from '@umijs/max';
import { Alert, Descriptions, Modal, Spin, Typography } from 'antd';
import React, { useEffect, useMemo, useState } from 'react';
import SourceIp from '@/components/SourceIp';
import { getCredentialEvidence, type CredentialEvidenceView } from '@/services/honeypot/api';

export interface CredentialEvidenceTarget {
  artifactId: string;
  adapterKey: string;
}

/** 原文仅保留在当前弹窗内；关闭、切换目标及卸载后不再接收旧请求的响应。 */
const CredentialEvidenceModal: React.FC<{
  target: CredentialEvidenceTarget | null;
  onClose: () => void;
}> = ({ target, onClose }) => {
  const intl = useIntl();
  const t = (id: string) => intl.formatMessage({ id: `events.${id}` });
  const [evidence, setEvidence] = useState<CredentialEvidenceView>();
  const [loading, setLoading] = useState(false);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    let active = true;
    const controller = new AbortController();
    setEvidence(undefined);
    setFailed(false);
    setLoading(Boolean(target));
    if (target) {
      void getCredentialEvidence(target.artifactId, { signal: controller.signal })
        .then((response) => {
          if (!active) return;
          if (response.success && response.data) setEvidence(response.data);
          else setFailed(true);
        })
        .catch(() => { if (active) setFailed(true); })
        .finally(() => { if (active) setLoading(false); });
    }
    return () => {
      active = false;
      controller.abort();
    };
  }, [target]);

  const fields = useMemo<Record<string, unknown>>(() => {
    if (!evidence) return {};
    try {
      const value: unknown = JSON.parse(evidence.content);
      return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : {};
    } catch {
      return {};
    }
  }, [evidence]);
  const value = (name: string) => typeof fields[name] === 'string' ? fields[name] as string : '-';
  const hasPassword = typeof fields.password === 'string';
  // 直接卸载弹窗，避免关闭动画缓存上一帧的敏感内容。
  if (!target) return null;

  return (
    <Modal title={t('evidence.title')} open={Boolean(target)} onCancel={() => { setEvidence(undefined); onClose(); }} footer={null} destroyOnHidden width={760}>
      {loading && <Spin />}
      {failed && <Alert type="warning" title={t('evidence.failed')} showIcon />}
      {evidence && evidence.summary.credentialArtifactId === target.artifactId && <>
        <Alert type="info" title={t('evidence.audited')} showIcon style={{ marginBottom: 16 }} />
        <Descriptions column={1} bordered size="small" items={[
          { key: 'sourceIp', label: t('sourceIp'), children: <SourceIp ip={evidence.summary.sourceIp} /> },
          { key: 'account', label: t('account'), children: value('username') },
          { key: 'domain', label: t('domain'), children: value('domain') },
          { key: 'method', label: t('method'), children: value('method') },
          { key: 'password', label: t('evidence.password'), children: hasPassword ? <Typography.Text code style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{fields.password === '' ? t('evidence.emptyPassword') : fields.password as string}</Typography.Text> : t(target.adapterKey === 'rdp' ? 'evidence.ntlm' : 'evidence.noPassword') },
          { key: 'artifact', label: t('evidence.id'), children: evidence.summary.credentialArtifactId },
        ]} />
        {evidence.summary.truncated && <Alert type="warning" title={t('evidence.truncated')} style={{ marginTop: 16 }} />}
        <details style={{ marginTop: 16 }}>
          <summary>{t('evidence.raw')}</summary>
          <pre style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', maxHeight: 320, overflow: 'auto' }}>{evidence.content}</pre>
        </details>
      </>}
    </Modal>
  );
};

export default CredentialEvidenceModal;
