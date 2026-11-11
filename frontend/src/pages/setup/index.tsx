import { Button, Card, Form, Input, Typography, message } from 'antd';
import React, { useState } from 'react';
import { history, useModel } from '@umijs/max';
import { initializeSystem, login, setAccessToken, toCurrentUser } from '@/services/identity';

interface SetupForm {
  username: string;
  password: string;
  confirmPassword: string;
}

const SetupPage: React.FC = () => {
  const { setInitialState } = useModel('@@initialState');
  const [submitting, setSubmitting] = useState(false);

  const submit = async ({ username, password }: SetupForm) => {
    setSubmitting(true);
    try {
      await initializeSystem({ username, password });
      const response = await login({ username, password });
      if (response.data?.accessToken) setAccessToken(response.data.accessToken);
      await setInitialState((state) => ({ ...state, currentUser: toCurrentUser(response.data.user), initialized: true }));
      message.success('初始化完成');
      history.replace('/overview');
    } catch (error) {
      message.error(error instanceof Error ? error.message : '初始化失败');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div style={{ minHeight: '100vh', display: 'grid', placeItems: 'center', padding: 24 }}>
      <Card style={{ width: 420 }}>
        <Typography.Title level={3}>首次初始化</Typography.Title>
        <Typography.Paragraph type="secondary">
          当前系统还没有用户，请创建第一个管理员账号。
        </Typography.Paragraph>
        <Form layout="vertical" onFinish={submit}>
          <Form.Item name="username" label="管理员账号" rules={[{ required: true, min: 3, message: '请输入至少 3 个字符的账号' }]}>
            <Input autoComplete="username" />
          </Form.Item>
          <Form.Item name="password" label="密码" rules={[{ required: true, min: 8, message: '请输入至少 8 位密码' }]}>
            <Input.Password autoComplete="new-password" />
          </Form.Item>
          <Form.Item
            name="confirmPassword"
            label="确认密码"
            dependencies={['password']}
            rules={[{ required: true, message: '请再次输入密码' }, ({ getFieldValue }) => ({ validator: (_, value) => value === getFieldValue('password') ? Promise.resolve() : Promise.reject(new Error('两次密码不一致')) })]}
          >
            <Input.Password autoComplete="new-password" />
          </Form.Item>
          <Button type="primary" htmlType="submit" loading={submitting} block>完成初始化</Button>
        </Form>
      </Card>
    </div>
  );
};

export default SetupPage;
