import express, { Express, Request, Response } from 'express';
import crypto from 'node:crypto';
import cors from 'cors';
import { GatewayConfig, getConfig } from './config';
import { createProxyMiddleware } from './proxy';
import { SessionRoutingStore, defaultSessionRouter } from './sessionRouter';
import { MetricsCollector, defaultMetricsCollector } from './metrics';
import { SecurityEventRecorder, defaultEventRecorder } from './eventRecorder';

import { createOperatorAuthMiddleware, requireOperatorPermission } from './auth';

export function createApp(
  customConfig?: Partial<GatewayConfig>,
  customSessionRouter?: SessionRoutingStore,
  customMetricsCollector?: MetricsCollector,
  customEventRecorder?: SecurityEventRecorder
): Express {
  const config: GatewayConfig = {
    ...getConfig(),
    ...customConfig,
  };
  const sessionRouter = customSessionRouter || defaultSessionRouter;
  const metricsCollector = customMetricsCollector || defaultMetricsCollector;
  const eventRecorder = customEventRecorder || defaultEventRecorder;
  const operatorAuth = createOperatorAuthMiddleware(config);

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
    const metrics = metricsCollector.getSummary(
      sessionRouter.getActiveDeceptionCount(),
      config.emergencyDisableDiversion,
      config.routingMode
    );

    res.status(200).json({
      status: 'healthy',
      service: 'gateway',
      stage: 'Stage 6 — Security Hardening and Operator Authentication',
      upstream: config.originUrl,
      detectionService: config.detectionServiceUrl,
      detectionEnabled: config.detectionEnabled,
      routingMode: config.routingMode,
      emergencyDisableDiversion: config.emergencyDisableDiversion,
      deceptionService: config.deceptionServiceUrl,
      deceptionThreshold: config.deceptionScoreThreshold,
      activeDeceptionSessions: sessionRouter.getActiveDeceptionCount(),
      deceptionFailurePolicy: config.deceptionFailurePolicy,
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      metrics: {
        totalRequests: metrics.totalRequests,
        routingBreakdown: metrics.routingBreakdown,
        quarantinedRequests: metrics.quarantinedRequests,
        gatewayLatencyP50Ms: metrics.gatewayLatency.p50Ms,
        gatewayLatencyP95Ms: metrics.gatewayLatency.p95Ms,
      },
    });
  });

  // Body parser for administrative gateway endpoints only
  app.use('/api/gateway', express.json());

  // Operational metrics endpoint (Stage 8 Observability)
  app.get('/api/gateway/metrics', (_req: Request, res: Response) => {
    const summary = metricsCollector.getSummary(
      sessionRouter.getActiveDeceptionCount(),
      config.emergencyDisableDiversion,
      config.routingMode
    );
    res.status(200).json(summary);
  });

  // Gateway recent security events endpoint (Stage 8 Observability)
  app.get('/api/gateway/events', (req: Request, res: Response) => {
    const limit = parseInt((req.query.limit as string) || '50', 10);
    const events = eventRecorder.getRecentEvents(limit);
    res.status(200).json({
      events,
      total: events.length,
    });
  });

  // Administrative control: Emergency disable toggle (requires routing:control permission)
  app.post(
    '/api/gateway/emergency-disable',
    operatorAuth,
    requireOperatorPermission('routing:control'),
    (req: Request, res: Response) => {
      config.emergencyDisableDiversion = true;
      res.status(200).json({
        status: 'emergency_disable_activated',
        emergencyDisableDiversion: config.emergencyDisableDiversion,
        routingMode: config.routingMode,
        operator: req.operator?.username,
        timestamp: new Date().toISOString(),
      });
    }
  );

  app.post(
    '/api/gateway/emergency-enable',
    operatorAuth,
    requireOperatorPermission('routing:control'),
    (req: Request, res: Response) => {
      config.emergencyDisableDiversion = false;
      res.status(200).json({
        status: 'emergency_disable_deactivated',
        emergencyDisableDiversion: config.emergencyDisableDiversion,
        routingMode: config.routingMode,
        operator: req.operator?.username,
        timestamp: new Date().toISOString(),
      });
    }
  );

  // Administrative control: Reset active deception session(s) (requires sessions:reset permission)
  app.post(
    '/api/gateway/sessions/reset',
    operatorAuth,
    requireOperatorPermission('sessions:reset'),
    (req: Request, res: Response) => {
      const { sessionId } = req.body || {};
      if (sessionId && typeof sessionId === 'string') {
        const reset = sessionRouter.resetSessionAssignment(sessionId);
        res.status(200).json({
          status: reset ? 'session_cleared' : 'session_not_found',
          sessionId,
          activeDeceptionSessions: sessionRouter.getActiveDeceptionCount(),
          operator: req.operator?.username,
        });
        return;
      }

      sessionRouter.clearAllAssignments();
      res.status(200).json({
        status: 'all_sessions_cleared',
        activeDeceptionSessions: 0,
        operator: req.operator?.username,
        timestamp: new Date().toISOString(),
      });
    }
  );

  // All other traffic is handled by the secure reverse-proxy middleware with adaptive diversion
  app.use(createProxyMiddleware(config, sessionRouter, metricsCollector, eventRecorder));

  return app;
}

export const app = createApp();

