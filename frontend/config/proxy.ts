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
  },
};
