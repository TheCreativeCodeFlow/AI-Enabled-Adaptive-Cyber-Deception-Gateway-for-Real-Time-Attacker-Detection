import express, { Express, Request, Response } from 'express';
import crypto from 'node:crypto';
import cors from 'cors';
import { GatewayConfig, getConfig } from './config';
import { createProxyMiddleware } from './proxy';
import { SessionRoutingStore, defaultSessionRouter } from './sessionRouter';

export function createApp(
  customConfig?: Partial<GatewayConfig>,
  customSessionRouter?: SessionRoutingStore
): Express {
  const config: GatewayConfig = {
    ...getConfig(),
    ...customConfig,
  };
  const sessionRouter = customSessionRouter || defaultSessionRouter;

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
      stage: 'Stage 5 — Policy-Controlled Traffic Diversion',
      upstream: config.originUrl,
      detectionService: config.detectionServiceUrl,
      detectionEnabled: config.detectionEnabled,
      routingMode: config.routingMode,
      emergencyDisableDiversion: config.emergencyDisableDiversion,
      deceptionService: config.deceptionServiceUrl,
      deceptionThreshold: config.deceptionScoreThreshold,
      activeDeceptionSessions: sessionRouter.getActiveDeceptionCount(),
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
    });
  });

  // Body parser for administrative gateway endpoints only
  app.use('/api/gateway', express.json());

  // Administrative control: Emergency disable toggle
  app.post('/api/gateway/emergency-disable', (_req: Request, res: Response) => {
    config.emergencyDisableDiversion = true;
    res.status(200).json({
      status: 'emergency_disable_activated',
      emergencyDisableDiversion: config.emergencyDisableDiversion,
      routingMode: config.routingMode,
      timestamp: new Date().toISOString(),
    });
  });

  app.post('/api/gateway/emergency-enable', (_req: Request, res: Response) => {
    config.emergencyDisableDiversion = false;
    res.status(200).json({
      status: 'emergency_disable_deactivated',
      emergencyDisableDiversion: config.emergencyDisableDiversion,
      routingMode: config.routingMode,
      timestamp: new Date().toISOString(),
    });
  });

  // Administrative control: Reset active deception session(s)
  app.post('/api/gateway/sessions/reset', (req: Request, res: Response) => {
    const { sessionId } = req.body || {};
    if (sessionId && typeof sessionId === 'string') {
      const reset = sessionRouter.resetSessionAssignment(sessionId);
      res.status(200).json({
        status: reset ? 'session_cleared' : 'session_not_found',
        sessionId,
        activeDeceptionSessions: sessionRouter.getActiveDeceptionCount(),
      });
      return;
    }

    sessionRouter.clearAllAssignments();
    res.status(200).json({
      status: 'all_sessions_cleared',
      activeDeceptionSessions: 0,
      timestamp: new Date().toISOString(),
    });
  });

  // All other traffic is handled by the secure reverse-proxy middleware with adaptive diversion
  app.use(createProxyMiddleware(config, sessionRouter));

  return app;
}

export const app = createApp();

