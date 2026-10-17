import express, { Express, Request, Response } from 'express';
import crypto from 'node:crypto';
import cors from 'cors';
import { GatewayConfig, getConfig } from './config';
import { createProxyMiddleware } from './proxy';

export function createApp(customConfig?: Partial<GatewayConfig>): Express {
  const config: GatewayConfig = {
    ...getConfig(),
    ...customConfig,
  };

  const app = express();

  // Disable x-powered-by header
  app.disable('x-powered-by');

  // CORS support
  app.use(cors({ origin: '*' }));

  // Middleware: Request ID generation & propagation
  app.use((req: Request, res: Response, next) => {
    const existingId = req.headers['x-request-id'];
    const requestId =
      typeof existingId === 'string' && existingId.trim().length > 0
        ? existingId.trim()
        : crypto.randomUUID();

    req.headers['x-request-id'] = requestId;
    res.setHeader('X-Request-ID', requestId);
    next();
  });

  // Dedicated gateway health check (handled locally, not forwarded)
  app.get('/health', (_req: Request, res: Response) => {
    res.status(200).json({
      status: 'healthy',
      service: 'gateway',
      stage: 'Stage 2 — Secure Reverse-Proxy Gateway',
      upstream: config.originUrl,
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
    });
  });

  // All other traffic is handled by the secure reverse-proxy middleware
  app.use(createProxyMiddleware(config));

  return app;
}

export const app = createApp();
