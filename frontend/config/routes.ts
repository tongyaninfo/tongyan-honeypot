/** Honeypot 管理台路由。业务页面只展示服务端 API 返回的数据。 */
export default [
  {
    path: '/user',
    layout: false,
    routes: [
      {
        path: '/user/login',
        name: '登录',
        component: './auth/login',
      },
      {
        path: '/user',
        redirect: '/user/login',
      },
    ],
  },
  {
    path: '/setup',
    layout: false,
    component: './setup',
  },
  {
    path: '/overview',
    name: '运行总览',
    icon: 'dashboard',
    component: './overview',
  },
  {
    path: '/services',
    name: '服务实例',
    icon: 'cloudServer',
    component: './services',
  },
  {
    path: '/reports',
    name: '运行报告',
    icon: 'barChart',
    component: './reports',
  },
  {
    path: '/sensors',
    redirect: '/services',
  },
  {
    path: '/events',
    name: '威胁事件',
    icon: 'alert',
    component: './events',
  },
  {
    path: '/threats',
    name: '威胁清单',
    icon: 'securityScan',
    component: './threats',
  },
  {
    path: '/credentials',
    name: '认证证据',
    icon: 'key',
    component: './credentials',
  },
  {
    path: '/system',
    name: '系统管理',
    icon: 'setting',
    access: 'canAdmin',
    routes: [
      { path: '/system', redirect: '/system/ip-location' },
      { path: '/system/ip-location', name: 'IP 数据库配置', component: './system/ip-location', access: 'canAdmin' },
      { path: '/system/notifications', name: '通知设置', component: './system/notifications', access: 'canAdmin' },
      { path: '/system/mail-records', name: '邮件记录', component: './system/mail-records', access: 'canAdmin' },
      { path: '/system/syslog', name: 'Syslog 配置', component: './system/syslog', access: 'canAdmin' },
      { path: '/system/mcp', name: 'MCP 服务', component: './system/mcp', access: 'canAdmin' },
    ],
  },
  {
    path: '/',
    redirect: '/overview',
  },
  {
    component: './exception/404',
    path: '/*',
  },
];
