import dotenv from 'dotenv';
import { app } from './app';

dotenv.config();

const PORT = parseInt(process.env.PORT || '4000', 10);
const HOST = process.env.HOST || '0.0.0.0';

const server = app.listen(PORT, HOST, () => {
  console.log(`[Backend] Deception Gateway API running on http://${HOST}:${PORT}`);
  console.log(`[Backend] Health check available at http://${HOST}:${PORT}/health`);
});

const handleShutdown = (signal: string) => {
  console.log(`[Backend] Received ${signal}. Initiating graceful shutdown...`);
  server.close(() => {
    console.log('[Backend] HTTP server closed cleanly.');
    process.exit(0);
  });

  // Force exit after 5 seconds if connections hang
  setTimeout(() => {
    console.error('[Backend] Forcing process termination after timeout.');
    process.exit(1);
  }, 5000).unref();
};

process.on('SIGTERM', () => handleShutdown('SIGTERM'));
process.on('SIGINT', () => handleShutdown('SIGINT'));
