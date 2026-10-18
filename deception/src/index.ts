import { createApp } from './app';
import { getConfig } from './config';

const config = getConfig();
const app = createApp();

const server = app.listen(config.port, config.host, () => {
  console.log(`[Deception-Runtime] Listening on http://${config.host}:${config.port}`);
  console.log(`[Deception-Runtime] Health check available at http://${config.host}:${config.port}/health`);
  console.log(`[Deception-Runtime] Deception State Graph & Synthetic APIs active`);
});

const gracefulShutdown = (signal: string) => {
  console.log(`[Deception-Runtime] Received ${signal}. Performing graceful shutdown...`);
  server.close(() => {
    console.log('[Deception-Runtime] HTTP server closed. Process exiting.');
    process.exit(0);
  });
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));
