import jwt from 'jsonwebtoken';
import { Request, Response, NextFunction } from 'express';
import { GatewayConfig } from './config';
import { logRequest } from './logger';

export interface OperatorTokenPayload {
  sub: string;
  username: string;
  email: string;
  role: 'admin' | 'analyst';
  permissions: string[];
  sessionId?: string;
}

declare global {
  namespace Express {
    interface Request {
      operator?: OperatorTokenPayload;
    }
  }
}

// In-memory sliding rate limiter for gateway operator control operations
const OPERATOR_ACTION_COUNTS = new Map<string, { count: number; windowStart: number }>();
const MAX_ACTIONS_PER_MINUTE = 30;
const WINDOW_MS = 60 * 1000;

function checkOperatorRateLimit(operatorKey: string): boolean {
  const now = Date.now();
  const entry = OPERATOR_ACTION_COUNTS.get(operatorKey);

  if (!entry || now - entry.windowStart > WINDOW_MS) {
    OPERATOR_ACTION_COUNTS.set(operatorKey, { count: 1, windowStart: now });
    return true;
  }

  if (entry.count >= MAX_ACTIONS_PER_MINUTE) {
    return false;
  }

  entry.count += 1;
  return true;
}

export function createOperatorAuthMiddleware(config: GatewayConfig) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const authHeader = req.headers.authorization;
    const clientIp = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || 'unknown';
    const requestId = (req.headers['x-request-id'] as string) || (res.getHeader('X-Request-ID') as string) || 'unknown';

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      logRequest({
        timestamp: new Date().toISOString(),
        requestId,
        method: req.method,
        path: req.originalUrl,
        statusCode: 401,
        durationMs: 0,
        clientIp,
        error: 'Unauthorized: Missing or malformed Bearer token for privileged control API',
      });

      res.status(401).json({
        error: 'Unauthorized',
        message: 'Operator authentication required to access gateway control APIs.',
        requestId,
      });
      return;
    }

    const token = authHeader.split(' ')[1];
    try {
      const payload = jwt.verify(token, config.operatorJwtSecret, {
        algorithms: ['HS256'],
      }) as OperatorTokenPayload;

      req.operator = payload;

      // Rate limit check per operator
      const rateKey = `${clientIp}:${payload.username}`;
      if (!checkOperatorRateLimit(rateKey)) {
        res.status(429).json({
          error: 'Too Many Requests',
          message: 'Rate limit exceeded for operator management operations.',
          requestId,
        });
        return;
      }

      next();
    } catch (err: any) {
      logRequest({
        timestamp: new Date().toISOString(),
        requestId,
        method: req.method,
        path: req.originalUrl,
        statusCode: 401,
        durationMs: 0,
        clientIp,
        error: `Unauthorized: Invalid token (${err.message})`,
      });

      res.status(401).json({
        error: 'Unauthorized',
        message: 'Invalid or expired operator authentication token.',
        requestId,
      });
    }
  };
}

export function requireOperatorPermission(permission: string) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const clientIp = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || 'unknown';
    const requestId = (req.headers['x-request-id'] as string) || (res.getHeader('X-Request-ID') as string) || 'unknown';

    if (!req.operator) {
      res.status(401).json({
        error: 'Unauthorized',
        message: 'Operator authentication required.',
        requestId,
      });
      return;
    }

    const hasPermission =
      req.operator.role === 'admin' ||
      (Array.isArray(req.operator.permissions) && req.operator.permissions.includes(permission));

    if (!hasPermission) {
      logRequest({
        timestamp: new Date().toISOString(),
        requestId,
        method: req.method,
        path: req.originalUrl,
        statusCode: 403,
        durationMs: 0,
        clientIp,
        error: `Forbidden: Operator ${req.operator.username} (role: ${req.operator.role}) lacks permission "${permission}"`,
      });

      res.status(403).json({
        error: 'Forbidden',
        message: `Insufficient permissions. Action requires "${permission}" permission. Administrator role required.`,
        requiredPermission: permission,
        operatorRole: req.operator.role,
        requestId,
      });
      return;
    }

    next();
  };
}
