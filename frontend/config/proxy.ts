/** 本地开发时将管理台请求转发到 Honeypot.Api。 */
export default {
  dev: {
    '/api/': {
      target: 'http://localhost:5080',
      changeOrigin: true,
    },
    '/hubs/': {
      target: 'http://localhost:5080',
      changeOrigin: true,
      ws: true,
    },
    // 保留浏览器 Host，使 MCP 同源检查与浏览器 Origin 一致。
    '/mcp': { target: 'http://localhost:5080', changeOrigin: false },
  },
  test: {
    '/api/': {
      target: 'http://localhost:5080',
      changeOrigin: true,
    },
    '/hubs/': {
      target: 'http://localhost:5080',
      changeOrigin: true,
      ws: true,
    },
    '/mcp': { target: 'http://localhost:5080', changeOrigin: false },
  },
};
