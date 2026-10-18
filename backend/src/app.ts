import express, { Request, Response } from 'express';
import cors from 'cors';
import { authRouter } from './routes/authRoutes';
import { auditRouter } from './routes/auditRoutes';
import { orgRouter } from './routes/orgRoutes';
import { appRouter } from './routes/appRoutes';
import { initDb } from './db';

export const app = express();

const corsOrigin = process.env.CORS_ORIGIN || '*';

app.disable('x-powered-by');
app.use(cors({ origin: corsOrigin }));
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

// Initialize database on boot
initDb().catch((err) => {
  console.error('[Backend-DB-Init-Error]', err);
});

// Root metadata route
app.get('/', (_req: Request, res: Response) => {
  res.json({
    service: 'deception-gateway-backend',
    version: '0.7.0',
    stage: 'Stage 7 — Multi-Tenant Organisation Management and Application Onboarding',
    healthCheck: '/health',
    authEndpoints: '/api/auth',
    orgEndpoints: '/api/orgs',
  });
});

// Required health check endpoint
app.get('/health', (_req: Request, res: Response) => {
  res.status(200).json({
    status: 'healthy',
    service: 'backend',
    stage: 'Stage 7',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
  });
});

// Mount authenticated operator API routes
app.use('/api/auth', authRouter);
app.use('/api/audit', auditRouter);
app.use('/api/orgs/:orgId/apps', appRouter);
app.use('/api/orgs', orgRouter);

// 404 handler
app.use((_req: Request, res: Response) => {
  res.status(404).json({
    error: 'Not Found',
    message: 'The requested resource does not exist.',
  });
});

