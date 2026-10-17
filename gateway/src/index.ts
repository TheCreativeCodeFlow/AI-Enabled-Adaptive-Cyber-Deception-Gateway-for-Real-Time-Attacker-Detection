import { app } from './app';
import { getConfig } from './config';

const config = getConfig();

const server = app.listen(config.port, config.host, () => {
  console.log(`[Gateway] Reverse-proxy listening on http://${config.host}:${config.port}`);
  console.log(`[Gateway] Configured upstream origin: ${config.originUrl}`);
  console.log(`[Gateway] Health check available at http://${config.host}:${config.port}/health`);
});

const handleShutdown = (signal: string) => {
  console.log(`[Gateway] Received ${signal}. Initiating graceful shutdown...`);
  server.close(() => {
    console.log('[Gateway] HTTP server closed cleanly.');
    process.exit(0);
  });

  // Force shutdown after timeout if connections remain open
  setTimeout(() => {
    console.error('[Gateway] Forcing shutdown after timeout.');
    process.exit(1);
  }, 5000).unref();
};

process.on('SIGTERM', () => handleShutdown('SIGTERM'));
process.on('SIGINT', () => handleShutdown('SIGINT'));
