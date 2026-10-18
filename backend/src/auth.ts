import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import crypto from 'node:crypto';
import { Request, Response, NextFunction } from 'express';
import { getConfig } from './config';
import { query, OperatorRecord } from './db';

export interface OperatorPayload {
  sub: string;
  username: string;
  email: string;
  role: 'admin' | 'analyst';
  permissions: string[];
  sessionId: string;
}

export type Permission =
  | 'routing:read'
  | 'routing:control'
  | 'sessions:read'
  | 'sessions:reset'
  | 'audit:read'
  | 'operators:manage';

export const ROLE_PERMISSIONS: Record<'admin' | 'analyst', Permission[]> = {
  admin: [
    'routing:read',
    'routing:control',
    'sessions:read',
    'sessions:reset',
    'audit:read',
    'operators:manage',
  ],
  analyst: ['routing:read', 'sessions:read', 'audit:read'],
};

// Rate limiting in-memory store for login attempts (IP + username)
interface FailedAttempt {
  count: number;
  firstAttempt: number;
  blockedUntil?: number;
}
const LOGIN_ATTEMPTS = new Map<string, FailedAttempt>();
const MAX_LOGIN_ATTEMPTS = 5;
const ATTEMPT_WINDOW_MS = 15 * 60 * 1000; // 15 minutes
const BLOCK_DURATION_MS = 15 * 60 * 1000; // 15 minutes block

export function checkLoginRateLimit(key: string): { allowed: boolean; retryAfterSeconds?: number } {
  const now = Date.now();
  const attempt = LOGIN_ATTEMPTS.get(key);

  if (!attempt) {
    return { allowed: true };
  }

  if (attempt.blockedUntil && attempt.blockedUntil > now) {
    const retryAfter = Math.ceil((attempt.blockedUntil - now) / 1000);
    return { allowed: false, retryAfterSeconds: retryAfter };
  }

  // If window expired, reset
  if (now - attempt.firstAttempt > ATTEMPT_WINDOW_MS) {
    LOGIN_ATTEMPTS.delete(key);
    return { allowed: true };
  }

  if (attempt.count >= MAX_LOGIN_ATTEMPTS) {
    attempt.blockedUntil = now + BLOCK_DURATION_MS;
    return { allowed: false, retryAfterSeconds: Math.ceil(BLOCK_DURATION_MS / 1000) };
  }

  return { allowed: true };
}

export function recordFailedLogin(key: string): void {
  const now = Date.now();
  const attempt = LOGIN_ATTEMPTS.get(key);

  if (!attempt || now - attempt.firstAttempt > ATTEMPT_WINDOW_MS) {
    LOGIN_ATTEMPTS.set(key, { count: 1, firstAttempt: now });
  } else {
    attempt.count += 1;
    if (attempt.count >= MAX_LOGIN_ATTEMPTS) {
      attempt.blockedUntil = now + BLOCK_DURATION_MS;
    }
  }
}

export function clearFailedLogin(key: string): void {
  LOGIN_ATTEMPTS.delete(key);
}

export async function hashPassword(password: string): Promise<string> {
  const config = getConfig();
  return bcrypt.hash(password, config.bcryptSaltRounds);
}

export async function comparePassword(password: string, hash: string): Promise<boolean> {
  return bcrypt.compare(password, hash);
}

export function generateOperatorToken(operator: OperatorRecord): { token: string; sessionId: string; expiresIn: string } {
  const config = getConfig();
  const permissions = ROLE_PERMISSIONS[operator.role] || [];
  const sessionId = crypto.randomBytes(24).toString('base64url');

  const payload: OperatorPayload = {
    sub: operator.id,
    username: operator.username,
    email: operator.email,
    role: operator.role,
    permissions,
    sessionId,
  };

  const token = jwt.sign(payload, config.jwtSecret, {
    expiresIn: config.jwtExpiresIn as any,
    algorithm: 'HS256',
  });

  return { token, sessionId, expiresIn: config.jwtExpiresIn };
}

export function verifyOperatorToken(token: string): OperatorPayload {
  const config = getConfig();
  return jwt.verify(token, config.jwtSecret, { algorithms: ['HS256'] }) as OperatorPayload;
}

export async function logAuditEvent(
  action: string,
  status: 'SUCCESS' | 'FAILED' | 'FORBIDDEN',
  ipAddress: string,
  operator?: { id?: string; username?: string },
  details: Record<string, any> = {}
): Promise<void> {
  // Redact any potential credentials from details
  const sanitizedDetails = { ...details };
  delete sanitizedDetails.password;
  delete sanitizedDetails.token;
  delete sanitizedDetails.authorization;
  delete sanitizedDetails.cookie;

  try {
    await query(
      `INSERT INTO audit_logs (operator_id, operator_username, action, status, ip_address, details)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [
        operator?.id || null,
        operator?.username || 'anonymous',
        action,
        status,
        ipAddress,
        JSON.stringify(sanitizedDetails),
      ]
    );
  } catch (err: any) {
    console.error(`[Audit-Log-Error] Failed to persist audit log: ${err.message}`);
  }
}

// Express Request augmentation
declare global {
  namespace Express {
    interface Request {
      operator?: OperatorPayload;
    }
  }
}

/**
 * Authentication Middleware: Validates Bearer token in Authorization header.
 */
export function requireAuth(req: Request, res: Response, next: NextFunction): void {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    res.status(401).json({
      error: 'Unauthorized',
      message: 'Valid operator authentication token is required.',
    });
    return;
  }

  const token = authHeader.split(' ')[1];
  try {
    const payload = verifyOperatorToken(token);
    req.operator = payload;
    next();
  } catch (err: any) {
    res.status(401).json({
      error: 'Unauthorized',
      message: 'Invalid or expired operator authentication token.',
    });
  }
}

/**
 * RBAC Middleware: Enforces explicit permission required for route.
 */
export function requirePermission(permission: Permission) {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.operator) {
      res.status(401).json({
        error: 'Unauthorized',
        message: 'Authentication required.',
      });
      return;
    }

    if (!req.operator.permissions || !req.operator.permissions.includes(permission)) {
      logAuditEvent(
        'ACCESS_DENIED',
        'FORBIDDEN',
        req.ip || 'unknown',
        { id: req.operator.sub, username: req.operator.username },
        { requiredPermission: permission, userRole: req.operator.role, path: req.originalUrl }
      );

      res.status(403).json({
        error: 'Forbidden',
        message: `Insufficient permissions. Action requires "${permission}" permission.`,
        requiredPermission: permission,
        role: req.operator.role,
      });
      return;
    }

    next();
  };
}
