import crypto from 'crypto';
import express, { NextFunction, Request, Response } from 'express';
import { DeceptionConfig, getConfig } from './config';
import { executeTransition, resolveNodeFromPath, validateTransition } from './dsg';
import { PROTECTED_POLICY } from './policy';
import { InMemorySessionStore, SessionStore } from './sessionStore';
import { applyDeceptionStrategy, selectDeceptionStrategy } from './strategy';
import { SYNTHETIC_ACCOUNTS } from './syntheticData';
import { DeceptionErrorResponse, DeceptionSession, DsgNodeId } from './types';

// Extend Express Request with session and requestId
declare global {
  namespace Express {
    interface Request {
      deceptionSession?: DeceptionSession;
      requestId?: string;
    }
  }
}

export function createApp(customStore?: SessionStore, customConfig?: Partial<DeceptionConfig>): express.Application {
  const config = { ...getConfig(), ...customConfig };
  const sessionStore = customStore || new InMemorySessionStore(config.maxSessions, config.sessionTtlMs);

  const app = express();

  // Basic security and request parsing
  app.disable('x-powered-by');

  // Request ID middleware
  app.use((req: Request, res: Response, next: NextFunction) => {
    req.requestId = (req.headers['x-request-id'] as string) || crypto.randomUUID();
    res.setHeader('X-Request-ID', req.requestId);
    next();
  });

  // Body parser with size limits
  app.use(express.json({ limit: config.maxRequestBodySize }));
  app.use(express.urlencoded({ extended: true, limit: config.maxRequestBodySize }));

  // Session identification and tracking middleware
  app.use((req: Request, res: Response, next: NextFunction) => {
    // Health check bypasses session tracking to remain stateless
    if (req.path === '/health') {
      return next();
    }

    const rawSessionId = req.headers['x-session-id'] as string;
    let session = rawSessionId ? sessionStore.getSession(rawSessionId) : null;

    if (!session) {
      session = sessionStore.createSession(rawSessionId);
    }

    req.deceptionSession = session;
    res.setHeader('X-Session-ID', session.sessionId);
    res.setHeader('X-Deception-Runtime', 'active');
    next();
  });

  // DSG Navigation & Observation Tracker Middleware
  const dsgTracker = (req: Request, res: Response, next: NextFunction) => {
    const session = req.deceptionSession;
    if (!session) {
      return next();
    }

    const targetNode: DsgNodeId = resolveNodeFromPath(req.path);
    const transitionCheck = validateTransition(session.currentNode, targetNode);

    if (!transitionCheck.valid) {
      const errRes: DeceptionErrorResponse = {
        error: 'Bad Request',
        message: transitionCheck.reason || 'Invalid DSG transition.',
        code: 'INVALID_DSG_TRANSITION',
        requestId: req.requestId,
        timestamp: new Date().toISOString(),
      };
      res.status(400).json(errRes);
      return;
    }

    // Execute node transition
    executeTransition(session, targetNode);

    // Apply deterministic deception strategy
    const proposedStrategy = selectDeceptionStrategy(session, {
      method: req.method,
      path: req.path,
      statusCode: 200,
    });
    applyDeceptionStrategy(session, proposedStrategy);

    // Expose current DSG state in headers for verification
    res.setHeader('X-DSG-Current-Node', session.currentNode);
    res.setHeader('X-DSG-Observation-Level', session.observationLevel);

    // Record interaction in observation layer
    if (session.interactions.length < PROTECTED_POLICY.maxInteractionsPerSession) {
      session.interactions.push({
        timestamp: new Date().toISOString(),
        method: req.method,
        path: req.path,
        targetNode,
        statusCode: 200,
        strategyExecuted: proposedStrategy,
      });
    }

    sessionStore.saveSession(session);
    next();
  };

  // 1. Health check endpoint
  app.get('/health', (_req: Request, res: Response) => {
    res.json({
      status: 'healthy',
      service: 'deception-runtime',
      stage: 'Stage 4 — Dynamic Deception Runtime and DSG',
      policyVersion: PROTECTED_POLICY.version,
      activeSessions: sessionStore.getActiveCount(),
      uptime: process.uptime(),
      timestamp: new Date().toISOString(),
    });
  });

  // 2. Synthetic Catalog API
  app.get('/api/catalog', dsgTracker, (req: Request, res: Response) => {
    const session = req.deceptionSession!;
    res.json({
      service: 'catalog',
      sessionId: session.sessionId,
      currentNode: session.currentNode,
      totalCount: session.dynamicServices.length,
      services: session.dynamicServices,
      timestamp: new Date().toISOString(),
    });
  });

  // 3. Synthetic Users Directory API
  app.get('/api/users', dsgTracker, (req: Request, res: Response) => {
    const session = req.deceptionSession!;
    res.json({
      service: 'user_directory',
      sessionId: session.sessionId,
      currentNode: session.currentNode,
      totalCount: session.dynamicUsers.length,
      users: session.dynamicUsers,
      timestamp: new Date().toISOString(),
    });
  });

  // 4. Synthetic File Metadata Store API
  app.get('/api/files', dsgTracker, (req: Request, res: Response) => {
    const session = req.deceptionSession!;
    res.json({
      service: 'file_store',
      sessionId: session.sessionId,
      currentNode: session.currentNode,
      totalCount: session.dynamicFiles.length,
      files: session.dynamicFiles,
      timestamp: new Date().toISOString(),
    });
  });

  // 5. Simulated Administration Console API
  app.get('/api/admin', dsgTracker, (req: Request, res: Response) => {
    const session = req.deceptionSession!;

    // Protected node: Requires admin authentication in session
    if (!session.authenticatedUser || session.authenticatedUser.role !== 'admin') {
      const errRes: DeceptionErrorResponse = {
        error: 'Unauthorized',
        message: 'Administrative console requires authenticated administrator credentials.',
        code: 'ADMIN_AUTH_REQUIRED',
        requestId: req.requestId,
        timestamp: new Date().toISOString(),
      };
      res.status(401).json(errRes);
      return;
    }

    res.json({
      service: 'admin_console',
      sessionId: session.sessionId,
      status: 'operational',
      currentNode: session.currentNode,
      authenticatedAs: session.authenticatedUser,
      adminMetrics: {
        activeHoneypots: session.dynamicServices.filter((s) => s.isDecoy).length,
        totalTrackedInteractions: session.interactions.length,
        observationFidelity: session.observationLevel,
        backupStatus: 'completed',
        auditEngine: 'active-isolation',
      },
      timestamp: new Date().toISOString(),
    });
  });

  // 6. Synthetic Authentication API
  app.post('/api/auth/login', dsgTracker, (req: Request, res: Response) => {
    const session = req.deceptionSession!;
    const { username, email, password } = req.body || {};

    const identifier = (username || email || '').trim().toLowerCase();
    const inputPassword = (password || '').trim();

    if (!identifier || !inputPassword) {
      const errRes: DeceptionErrorResponse = {
        error: 'Bad Request',
        message: 'Both username/email and password are required for synthetic authentication.',
        code: 'MISSING_CREDENTIALS',
        requestId: req.requestId,
        timestamp: new Date().toISOString(),
      };
      res.status(400).json(errRes);
      return;
    }

    // Match against explicitly documented synthetic test accounts
    const matchedAccount = SYNTHETIC_ACCOUNTS.find(
      (acc) =>
        (acc.username.toLowerCase() === identifier || acc.email.toLowerCase() === identifier) &&
        acc.passwordHash === inputPassword
    );

    if (!matchedAccount) {
      const errRes: DeceptionErrorResponse = {
        error: 'Unauthorized',
        message: 'Invalid synthetic credentials. Authentication failed.',
        code: 'INVALID_CREDENTIALS',
        requestId: req.requestId,
        timestamp: new Date().toISOString(),
      };
      res.status(401).json(errRes);
      return;
    }

    // Issue synthetic session token and update session role
    const syntheticToken = `syn_tok_${crypto.randomUUID().replace(/-/g, '')}`;
    session.authenticatedUser = {
      id: matchedAccount.userRecordId,
      username: matchedAccount.username,
      email: matchedAccount.email,
      role: matchedAccount.role,
      token: syntheticToken,
    };
    sessionStore.saveSession(session);

    res.status(200).json({
      status: 'authenticated',
      message: 'Synthetic authentication successful.',
      sessionId: session.sessionId,
      token: syntheticToken,
      user: {
        id: matchedAccount.userRecordId,
        username: matchedAccount.username,
        email: matchedAccount.email,
        role: matchedAccount.role,
      },
      timestamp: new Date().toISOString(),
    });
  });

  // 404 Catch-All Handler
  app.use((req: Request, res: Response) => {
    const errRes: DeceptionErrorResponse = {
      error: 'Not Found',
      message: `Endpoint "${req.method} ${req.path}" does not exist in synthetic deception runtime.`,
      code: 'RESOURCE_NOT_FOUND',
      requestId: req.requestId,
      timestamp: new Date().toISOString(),
    };
    res.status(404).json(errRes);
  });

  // Global Error Handler (including 413 Payload Too Large)
  app.use((err: any, req: Request, res: Response, _next: NextFunction) => {
    if (err.type === 'entity.too.large' || err.status === 413) {
      const errRes: DeceptionErrorResponse = {
        error: 'Payload Too Large',
        message: `Request body exceeds maximum permitted size (${config.maxRequestBodySize} bytes).`,
        code: 'PAYLOAD_TOO_LARGE',
        requestId: req.requestId,
        timestamp: new Date().toISOString(),
      };
      res.status(413).json(errRes);
      return;
    }

    const errRes: DeceptionErrorResponse = {
      error: 'Internal Server Error',
      message: 'An unexpected error occurred in the deception runtime.',
      code: 'INTERNAL_ERROR',
      requestId: req.requestId,
      timestamp: new Date().toISOString(),
    };
    res.status(500).json(errRes);
  });

  return app;
}
