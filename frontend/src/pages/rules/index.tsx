import { Alert, Card, Col, Descriptions, Row, Statistic, Tag, Typography } from 'antd';
import React from 'react';

const RulesPage: React.FC = () => (
  <div>
    <Typography.Title level={3}>规则集</Typography.Title>
    <Alert
      message="认证策略：AlwaysFail"
      description="所有协议进入认证阶段后返回登录失败，同时保存原始认证材料到加密证据仓库。规则只更新风险和威胁状态，不直接修改宿主防火墙。"
      type="warning"
      showIcon
      style={{ marginBottom: 16 }}
    />
    <Row gutter={[16, 16]}>
      <Col xs={24} md={8}><Card><Statistic title="生效规则" value={0} suffix="条" /></Card></Col>
      <Col xs={24} md={8}><Card><Statistic title="观察规则" value={0} suffix="条" /></Card></Col>
      <Col xs={24} md={8}><Card><Statistic title="待回滚变更" value={0} suffix="项" /></Card></Col>
    </Row>
    <Card title="一期规则边界" style={{ marginTop: 16 }}>
      <Descriptions column={1} bordered size="small">
        <Descriptions.Item label="流程">草稿 → 观察 → 生效 → 回滚</Descriptions.Item>
        <Descriptions.Item label="认证">每次认证尝试均标记失败并增加风险分</Descriptions.Item>
        <Descriptions.Item label="证据">原始密码通过 credentialArtifactId 关联加密证据</Descriptions.Item>
        <Descriptions.Item label="阻断"><Tag color="orange">仅策略状态</Tag>一期不自动修改宿主防火墙</Descriptions.Item>
      </Descriptions>
    </Card>
  </div>
);

export default RulesPage;
