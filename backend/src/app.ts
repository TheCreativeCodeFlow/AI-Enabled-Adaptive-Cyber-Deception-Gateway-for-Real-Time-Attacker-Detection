import express, { Request, Response } from 'express';
import cors from 'cors';

export const app = express();

const corsOrigin = process.env.CORS_ORIGIN || '*';

app.use(cors({ origin: corsOrigin }));
app.use(express.json());

// Root metadata route
app.get('/', (_req: Request, res: Response) => {
  res.json({
    service: 'deception-gateway-backend',
    version: '0.1.0',
    stage: 'Stage 1 — Repository Foundation and Architecture',
    healthCheck: '/health',
  });
});

// Required health check endpoint
app.get('/health', (_req: Request, res: Response) => {
  res.status(200).json({
    status: 'healthy',
    service: 'backend',
    stage: 'Stage 1',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
  });
});

// 404 handler
app.use((_req: Request, res: Response) => {
  res.status(404).json({
    error: 'Not Found',
    message: 'The requested resource does not exist.',
  });
});
