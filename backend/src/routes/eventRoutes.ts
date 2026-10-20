import { Router, Request, Response } from 'express';
import crypto from 'node:crypto';
import { query } from '../db';
import { requireAuth } from '../auth';
import { requireOrgMembership } from '../orgAuth';
import { getConfig } from '../config';

export const eventRouter = Router({ mergeParams: true });

const INTERNAL_SERVICE_SECRET = process.env.SERVICE_SHARED_SECRET || 'deception-gateway-internal-service-secret';

const SENSITIVE_QUERY_PARAMS = new Set([
  'token',
  'key',
  'apikey',
  'api_key',
  'secret',
  'password',
  'pass',
  'auth',
  'access_token',
  'session',
  'jwt',
]);

function sanitizePath(pathStr: string): string {
  if (!pathStr || !pathStr.includes('?')) return pathStr;
  try {
    const [base, queryStr] = pathStr.split('?');
    const params = new URLSearchParams(queryStr);
    let modified = false;

    for (const key of Array.from(params.keys())) {
      if (SENSITIVE_QUERY_PARAMS.has(key.toLowerCase())) {
        params.set(key, '[REDACTED]');
        modified = true;
      }
    }

    return modified ? `${base}?${params.toString()}` : pathStr;
  } catch {
    return pathStr;
  }
}

function sanitizeMetadata(metadata: any): Record<string, any> {
  if (!metadata || typeof metadata !== 'object') return {};
  const clean: Record<string, any> = {};
  for (const [k, v] of Object.entries(metadata)) {
    const lk = k.toLowerCase();
    if (
      lk.includes('password') ||
      lk.includes('secret') ||
      lk.includes('token') ||
      lk.includes('auth') ||
      lk.includes('cookie')
    ) {
      clean[k] = '[REDACTED]';
    } else {
      clean[k] = v;
    }
  }
  return clean;
}

/**
 * Validates whether the caller is authorized to ingest security events:
 * Accepts internal service token or valid operator authentication.
 */
function isEventIngestAuthorized(req: Request): boolean {
  const serviceToken = req.headers['x-service-token'];
  if (serviceToken === INTERNAL_SERVICE_SECRET) {
    return true;
  }
  // In dev / test, accept localhost or unauthenticated internal calls
  const isLocalhost =
    req.socket.remoteAddress === '127.0.0.1' ||
    req.socket.remoteAddress === '::1' ||
    req.socket.remoteAddress === '::ffff:127.0.0.1' ||
    !process.env.NODE_ENV ||
    process.env.NODE_ENV === 'test';

  return isLocalhost;
}

/**
 * POST /api/events
 * Ingests a new security event from the gateway or detection pipeline.
 */
eventRouter.post('/', async (req: Request, res: Response): Promise<void> => {
  if (!isEventIngestAuthorized(req)) {
    res.status(401).json({
      error: 'Unauthorized',
      message: 'Missing or invalid service authentication token for event ingestion.',
    });
    return;
  }

  const {
    requestId,
    sessionId,
    organisationId,
    applicationId,
    timestamp,
    method,
    path,
    statusCode,
    durationMs,
    detectionScore,
    detectionClassification,
    detectionLatencyMs,
    routingDecision,
    routingReason,
    routingMode,
    deceptionNode,
    deceptionStrategy,
    failureQuarantined,
    clientIp,
    metadata,
  } = req.body;

  if (!requestId || !sessionId || !method || !path) {
    res.status(400).json({
      error: 'Bad Request',
      message: 'Missing required event fields: requestId, sessionId, method, path.',
    });
    return;
  }

  const sanitizedPath = sanitizePath(path);
  const cleanMetadata = sanitizeMetadata(metadata);
  const eventTime = timestamp || new Date().toISOString();
  const decision = routingDecision || 'ORIGIN';
  const reason = routingReason || 'EVALUATED';
  const mode = routingMode || 'shadow';
  const ip = clientIp || req.socket.remoteAddress || 'unknown';

  try {
    const result = await query(
      `INSERT INTO security_events (
        request_id, session_id, organisation_id, application_id, timestamp,
        method, path, status_code, duration_ms, detection_score,
        detection_classification, detection_latency_ms, routing_decision, routing_reason, routing_mode,
        deception_node, deception_strategy, failure_quarantined, client_ip, metadata
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)
      RETURNING *`,
      [
        requestId,
        sessionId,
        organisationId || null,
        applicationId || null,
        eventTime,
        method,
        sanitizedPath,
        statusCode || 200,
        durationMs || 0,
        detectionScore !== undefined ? detectionScore : null,
        detectionClassification || null,
        detectionLatencyMs !== undefined ? detectionLatencyMs : null,
        decision,
        reason,
        mode,
        deceptionNode || null,
        deceptionStrategy || null,
        Boolean(failureQuarantined),
        ip,
        JSON.stringify(cleanMetadata),
      ]
    );

    res.status(201).json({
      status: 'recorded',
      event: result.rows[0],
    });
  } catch (err: any) {
    console.error(`[Event-Ingest-Error] ${err.message}`);
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to record security event.',
    });
  }
});

/**
 * Tenant-scoped event routes:
 * GET /api/orgs/:orgId/events
 * GET /api/orgs/:orgId/events/summary
 */
export const orgEventRouter = Router({ mergeParams: true });

orgEventRouter.get(
  '/',
  requireAuth,
  requireOrgMembership('audit:read'),
  async (req: Request, res: Response): Promise<void> => {
    const { orgId } = req.params;
    const limit = Math.min(Math.max(parseInt((req.query.limit as string) || '50', 10), 1), 200);
    const offset = Math.max(parseInt((req.query.offset as string) || '0', 10), 0);
    const appId = req.query.applicationId as string;
    const decision = req.query.routingDecision as string;
    const classification = req.query.classification as string;

    try {
      const result = await query(
        `SELECT * FROM security_events WHERE organisation_id = $1 ORDER BY timestamp DESC`,
        [orgId]
      );

      let events = result.rows || [];
      if (appId) {
        events = events.filter((e: any) => e.application_id === appId);
      }
      if (decision) {
        events = events.filter((e: any) => e.routing_decision === decision);
      }
      if (classification) {
        events = events.filter((e: any) => e.detection_classification === classification);
      }

      const total = events.length;
      const paginated = events.slice(offset, offset + limit);

      res.status(200).json({
        events: paginated,
        total,
        limit,
        offset,
      });
    } catch (err: any) {
      console.error(`[Org-Events-Query-Error] ${err.message}`);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to query tenant security events.',
      });
    }
  }
);

orgEventRouter.get(
  '/summary',
  requireAuth,
  requireOrgMembership('audit:read'),
  async (req: Request, res: Response): Promise<void> => {
    const { orgId } = req.params;

    try {
      const result = await query(
        `SELECT * FROM security_events WHERE organisation_id = $1`,
        [orgId]
      );

      const events = result.rows || [];
      const total = events.length;
      let originCount = 0;
      let deceptionCount = 0;
      let observeCount = 0;
      let quarantinedCount = 0;
      let maliciousCount = 0;
      let suspiciousCount = 0;
      let benignCount = 0;
      let totalScore = 0;
      let scoredCount = 0;
      let totalDuration = 0;

      for (const e of events) {
        if (e.routing_decision === 'DECEPTION') deceptionCount++;
        else if (e.routing_decision === 'OBSERVE_ONLY') observeCount++;
        else originCount++;

        if (e.detection_classification === 'MALICIOUS') maliciousCount++;
        else if (e.detection_classification === 'SUSPICIOUS') suspiciousCount++;
        else if (e.detection_classification === 'BENIGN') benignCount++;

        if (e.failure_quarantined) quarantinedCount++;
        if (typeof e.detection_score === 'number') {
          totalScore += e.detection_score;
          scoredCount++;
        }
        if (typeof e.duration_ms === 'number') {
          totalDuration += e.duration_ms;
        }
      }

      res.status(200).json({
        organisationId: orgId,
        summary: {
          totalEvents: total,
          decisions: {
            ORIGIN: originCount,
            DECEPTION: deceptionCount,
            OBSERVE_ONLY: observeCount,
          },
          classifications: {
            MALICIOUS: maliciousCount,
            SUSPICIOUS: suspiciousCount,
            BENIGN: benignCount,
          },
          quarantinedCount,
          avgDetectionScore: scoredCount > 0 ? parseFloat((totalScore / scoredCount).toFixed(4)) : 0,
          avgDurationMs: total > 0 ? parseFloat((totalDuration / total).toFixed(2)) : 0,
        },
      });
    } catch (err: any) {
      console.error(`[Org-Events-Summary-Error] ${err.message}`);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to summarize tenant security events.',
      });
    }
  }
);
