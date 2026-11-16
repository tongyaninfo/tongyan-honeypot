import type { ClientRequest, IncomingMessage } from 'node:http';

/** 本地开发时将管理台请求转发到 Honeypot.Api。 */
const managementTarget = {
  target: 'https://localhost:5080',
  // 开发代理的上游固定为本机，允许其默认自签证书。
  secure: false,
};

const managementProxy = {
  '/api/': { ...managementTarget, changeOrigin: true },
  '/hubs/': { ...managementTarget, changeOrigin: true, ws: true },
  '/mcp': {
    ...managementTarget,
    changeOrigin: false,
    onProxyReq(proxyRequest: ClientRequest, request: IncomingMessage) {
      const { host, origin } = request.headers;
      // 本地开发页面仍可使用 HTTP。仅转换已经与开发页面 Host 匹配的 Origin。
      if (host && origin === `http://${host}`) {
        proxyRequest.setHeader('Origin', `https://${host}`);
      }
    },
  },
};

export default {
  dev: managementProxy,
  test: managementProxy,
};
