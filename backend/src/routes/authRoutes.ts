import { Router, Request, Response } from 'express';
import crypto from 'node:crypto';
import {
  hashPassword,
  comparePassword,
  generateOperatorToken,
  logAuditEvent,
  requireAuth,
  checkLoginRateLimit,
  recordFailedLogin,
  clearFailedLogin,
  ROLE_PERMISSIONS,
} from '../auth';
import { query, OperatorRecord } from '../db';

export const authRouter = Router();

// Email regex validator
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const USERNAME_REGEX = /^[a-zA-Z0-9_-]{3,32}$/;

/**
 * POST /api/auth/register
 * Registers a new local operator account.
 */
authRouter.post('/register', async (req: Request, res: Response) => {
  const { username, email, password, role = 'analyst' } = req.body || {};
  const clientIp = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || 'unknown';

  // Input validation
  if (!username || typeof username !== 'string' || !USERNAME_REGEX.test(username.trim())) {
    res.status(400).json({
      error: 'Bad Request',
      message: 'Username must be 3-32 alphanumeric characters, dashes, or underscores.',
    });
    return;
  }

  if (!email || typeof email !== 'string' || !EMAIL_REGEX.test(email.trim())) {
    res.status(400).json({
      error: 'Bad Request',
      message: 'A valid email address is required.',
    });
    return;
  }

  if (!password || typeof password !== 'string' || password.length < 8) {
    res.status(400).json({
      error: 'Bad Request',
      message: 'Password must be at least 8 characters long.',
    });
    return;
  }

  const assignedRole = role === 'admin' ? 'admin' : 'analyst';

  try {
    const passwordHash = await hashPassword(password);
    const result = await query(
      `INSERT INTO operators (username, email, password_hash, role)
       VALUES ($1, $2, $3, $4)
       RETURNING id, username, email, role, is_active, created_at`,
      [username.trim().toLowerCase(), email.trim().toLowerCase(), passwordHash, assignedRole]
    );

    const created: OperatorRecord = result.rows[0];

    await logAuditEvent(
      'OPERATOR_REGISTERED',
      'SUCCESS',
      clientIp,
      { id: created.id, username: created.username },
      { role: created.role, email: created.email }
    );

    res.status(201).json({
      status: 'created',
      message: 'Operator account created successfully.',
      operator: {
        id: created.id,
        username: created.username,
        email: created.email,
        role: created.role,
        permissions: ROLE_PERMISSIONS[created.role],
        createdAt: created.created_at,
      },
    });
  } catch (err: any) {
    if (err.code === '23505' || err.message?.includes('duplicate key')) {
      await logAuditEvent('OPERATOR_REGISTER_CONFLICT', 'FAILED', clientIp, undefined, {
        username,
        email,
      });

      res.status(409).json({
        error: 'Conflict',
        message: 'Username or email is already registered.',
      });
      return;
    }

    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to register operator account.',
    });
  }
});

/**
 * POST /api/auth/login
 * Authenticates operator credentials and issues a signed JWT.
 */
authRouter.post('/login', async (req: Request, res: Response) => {
  const { username, password } = req.body || {};
  const clientIp = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || 'unknown';

  if (!username || !password) {
    res.status(400).json({
      error: 'Bad Request',
      message: 'Username and password are required.',
    });
    return;
  }

  const rateLimitKey = `${clientIp}:${String(username).toLowerCase().trim()}`;
  const rateLimit = checkLoginRateLimit(rateLimitKey);

  if (!rateLimit.allowed) {
    await logAuditEvent('LOGIN_RATE_LIMITED', 'FAILED', clientIp, { username }, {
      retryAfterSeconds: rateLimit.retryAfterSeconds,
    });

    res.status(429).json({
      error: 'Too Many Requests',
      message: `Account login temporarily blocked due to repeated failed attempts. Try again in ${rateLimit.retryAfterSeconds} seconds.`,
      retryAfterSeconds: rateLimit.retryAfterSeconds,
    });
    return;
  }

  try {
    const result = await query(
      `SELECT id, username, email, password_hash, role, is_active, created_at, updated_at
       FROM operators
       WHERE username = $1`,
      [String(username).toLowerCase().trim()]
    );

    const operator: OperatorRecord | undefined = result.rows[0];

    if (!operator || !operator.is_active) {
      recordFailedLogin(rateLimitKey);
      await logAuditEvent('LOGIN_FAILED_UNKNOWN_USER', 'FAILED', clientIp, { username });

      res.status(401).json({
        error: 'Unauthorized',
        message: 'Invalid credentials.',
      });
      return;
    }

    const isValid = await comparePassword(password, operator.password_hash);
    if (!isValid) {
      recordFailedLogin(rateLimitKey);
      await logAuditEvent('LOGIN_FAILED_BAD_PASSWORD', 'FAILED', clientIp, {
        id: operator.id,
        username: operator.username,
      });

      res.status(401).json({
        error: 'Unauthorized',
        message: 'Invalid credentials.',
      });
      return;
    }

    // Login successful: reset rate limiter
    clearFailedLogin(rateLimitKey);

    const tokenData = generateOperatorToken(operator);
    const tokenHash = crypto.createHash('sha256').update(tokenData.token).digest('hex');

    // Store server-managed session reference
    const expiresAt = new Date(Date.now() + 8 * 3600 * 1000).toISOString();
    await query(
      `INSERT INTO operator_sessions (id, operator_id, token_hash, expires_at)
       VALUES ($1, $2, $3, $4)`,
      [tokenData.sessionId, operator.id, tokenHash, expiresAt]
    );

    await logAuditEvent('LOGIN_SUCCESS', 'SUCCESS', clientIp, {
      id: operator.id,
      username: operator.username,
    }, {
      role: operator.role,
      sessionId: tokenData.sessionId,
    });

    res.status(200).json({
      status: 'authenticated',
      token: tokenData.token,
      expiresIn: tokenData.expiresIn,
      user: {
        id: operator.id,
        username: operator.username,
        email: operator.email,
        role: operator.role,
        permissions: ROLE_PERMISSIONS[operator.role],
      },
    });
  } catch (err: any) {
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Authentication processing error.',
    });
  }
});

/**
 * POST /api/auth/logout
 * Terminates active operator session.
 */
authRouter.post('/logout', requireAuth, async (req: Request, res: Response) => {
  const operator = req.operator!;
  const clientIp = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || 'unknown';

  try {
    if (operator.sessionId) {
      await query(
        `UPDATE operator_sessions SET revoked = true WHERE id = $1`,
        [operator.sessionId]
      );
    }

    await logAuditEvent('LOGOUT', 'SUCCESS', clientIp, {
      id: operator.sub,
      username: operator.username,
    }, {
      sessionId: operator.sessionId,
    });

    res.status(200).json({
      status: 'logged_out',
      message: 'Operator session terminated successfully.',
    });
  } catch (err: any) {
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Error terminating operator session.',
    });
  }
});

/**
 * GET /api/auth/me
 * Retrieves profile and permissions for currently authenticated operator.
 */
authRouter.get('/me', requireAuth, async (req: Request, res: Response) => {
  const operator = req.operator!;
  res.status(200).json({
    status: 'authenticated',
    operator: {
      id: operator.sub,
      username: operator.username,
      email: operator.email,
      role: operator.role,
      permissions: operator.permissions,
    },
  });
});
