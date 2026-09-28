// Dev-server proxy: the SPA and API share one origin in development, so the
// SameSite=Strict refresh cookie works exactly as it will behind a production reverse proxy.
export default {
  '/api': {
    target: process.env.API_URL ?? 'http://localhost:3000',
    secure: false,
    changeOrigin: false,
  },
};
