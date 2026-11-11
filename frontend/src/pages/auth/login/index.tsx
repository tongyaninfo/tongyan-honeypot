import { LockOutlined, SafetyCertificateOutlined, UserOutlined } from '@ant-design/icons';
import { Button, Card, Form, Input, Typography, message } from 'antd';
import { createStyles } from 'antd-style';
import React, { useState } from 'react';
import { history, useModel } from '@umijs/max';
import { Footer, LangDropdown } from '@/components';
import { login, setAccessToken, toCurrentUser } from '@/services/identity';

const useStyles = createStyles(({ token, css }) => ({
  page: css`
    min-height: 100vh;
    display: flex;
    flex-direction: column;
    overflow: auto;
    background:
      radial-gradient(circle at 0% 0%, rgba(22, 119, 255, 0.12), transparent 36%),
      linear-gradient(135deg, #f1f6ff 0%, #f8fbff 48%, #eef4ff 100%);
  `,
  header: css`
    width: min(1160px, calc(100% - 48px));
    margin: 0 auto;
    padding: 28px 0 12px;
    display: flex;
    align-items: center;
    justify-content: space-between;
  `,
  brand: css`
    display: inline-flex;
    align-items: center;
    gap: 12px;
    color: ${token.colorTextHeading};
    font-size: 20px;
    font-weight: 650;
    letter-spacing: 0.02em;
  `,
  brandLogo: css`
    width: 156px;
    height: auto;
    display: block;
  `,
  main: css`
    width: min(1160px, calc(100% - 48px));
    flex: 1;
    margin: 0 auto;
    padding: 64px 0 48px;
    display: grid;
    grid-template-columns: minmax(0, 1fr) minmax(360px, 460px);
    gap: 96px;
    align-items: center;

    @media (max-width: 820px) {
      grid-template-columns: 1fr;
      gap: 30px;
      padding: 32px 0 24px;
    }
  `,
  intro: css`
    padding: 12px 0;
  `,
  eyebrow: css`
    color: ${token.colorPrimary};
    font-size: 13px;
    font-weight: 700;
    letter-spacing: 0.24em;
  `,
  title: css`
    margin: 18px 0 12px !important;
    color: ${token.colorTextHeading} !important;
    font-size: clamp(32px, 4vw, 48px) !important;
    line-height: 1.18 !important;
    letter-spacing: -0.03em;
  `,
  subtitle: css`
    max-width: 520px;
    color: ${token.colorTextSecondary};
    font-size: 17px;
    line-height: 1.8;
  `,
  hint: css`
    margin-top: 30px;
    display: flex;
    align-items: center;
    gap: 10px;
    color: ${token.colorTextTertiary};
    font-size: 14px;
  `,
  card: css`
    border: 1px solid rgba(22, 119, 255, 0.08);
    border-radius: 18px;
    box-shadow: 0 24px 70px rgba(30, 64, 120, 0.14);
  `,
  cardAccent: css`
    width: 34px;
    height: 4px;
    margin-bottom: 24px;
    border-radius: 99px;
    background: ${token.colorPrimary};
  `,
  cardTitle: css`
    margin-bottom: 8px !important;
  `,
  cardDescription: css`
    margin-bottom: 28px !important;
    color: ${token.colorTextSecondary};
  `,
  submit: css`
    height: 46px;
    border-radius: 9px;
    font-size: 16px;
    font-weight: 600;
  `,
  footer: css`
    padding-top: 0;
  `,
}));

const getSafeRedirect = (value: string | null) => {
  if (!value?.startsWith('/') || value.startsWith('//')) return '/overview';
  try {
    const target = new URL(value, window.location.origin);
    return target.origin === window.location.origin
      ? `${target.pathname}${target.search}${target.hash}`
      : '/overview';
  } catch {
    return '/overview';
  }
};

const LoginPage: React.FC = () => {
  const { styles } = useStyles();
  const { setInitialState } = useModel('@@initialState');
  const [submitting, setSubmitting] = useState(false);

  const submit = async (values: { username: string; password: string }) => {
    setSubmitting(true);
    try {
      const response = await login(values);
      if (response.data?.accessToken) setAccessToken(response.data.accessToken);
      await setInitialState((state) => ({ ...state, currentUser: toCurrentUser(response.data.user), initialized: true }));
      message.success('登录成功');
      history.replace(getSafeRedirect(new URLSearchParams(history.location.search).get('redirect')));
    } catch (error) {
      message.error(error instanceof Error ? error.message : '登录失败，请检查账号和密码');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className={styles.page}>
      <header className={styles.header}>
        <div className={styles.brand}>
          <img className={styles.brandLogo} src="/assets/brand/tyinfo-logo-horizontal.png" alt="通研技术" />
        </div>
        <LangDropdown />
      </header>

      <main className={styles.main}>
        <section className={styles.intro} aria-labelledby="honeypot-login-title">
          <div className={styles.eyebrow}>HONEYPOT / CONSOLE</div>
          <Typography.Title id="honeypot-login-title" className={styles.title}>通研 Honeypot</Typography.Title>
          <Typography.Paragraph className={styles.subtitle}>
            蜜罐服务、攻击行为与认证证据，集中有序观测。
          </Typography.Paragraph>
          <div className={styles.hint}>
            <SafetyCertificateOutlined />
            <span>管理台仅允许授权用户访问，传感器可独立运行。</span>
          </div>
        </section>

        <Card className={styles.card} styles={{ body: { padding: '34px 36px 30px' } }}>
          <div className={styles.cardAccent} />
          <Typography.Title level={2} className={styles.cardTitle}>欢迎回来</Typography.Title>
          <Typography.Paragraph className={styles.cardDescription}>
            登录你的账号，进入蜜罐观测工作台。
          </Typography.Paragraph>
          <Form layout="vertical" onFinish={submit} requiredMark="optional">
            <Form.Item name="username" label="用户名" rules={[{ required: true, message: '请输入用户名' }]}>
              <Input size="large" prefix={<UserOutlined />} placeholder="请输入用户名" autoComplete="username" />
            </Form.Item>
            <Form.Item name="password" label="密码" rules={[{ required: true, message: '请输入密码' }]}>
              <Input.Password size="large" prefix={<LockOutlined />} placeholder="请输入密码" autoComplete="current-password" />
            </Form.Item>
            <Button className={styles.submit} type="primary" htmlType="submit" loading={submitting} block>
              登录管理平台
            </Button>
          </Form>
          <Typography.Paragraph type="secondary" style={{ margin: '24px 0 0', fontSize: 12 }}>
            请使用已创建的管理账号登录，并妥善保管账号信息。
          </Typography.Paragraph>
        </Card>
      </main>

      <div className={styles.footer}><Footer /></div>
    </div>
  );
};

export default LoginPage;
