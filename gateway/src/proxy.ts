import http from 'node:http';
import https from 'node:https';
import crypto from 'node:crypto';
import { Request, Response, NextFunction } from 'express';
import { GatewayConfig } from './config';
import { logRequest, sanitizePath } from './logger';
import { extractFeatures } from './features';
import { queryDetectionEngine, DetectionScoreResult } from './detector';
import { evaluateRoutingPolicy, ControllerDecision } from './controller';
import { SessionRoutingStore, defaultSessionRouter } from './sessionRouter';
import { MetricsCollector, defaultMetricsCollector } from './metrics';
import { SecurityEventRecorder, defaultEventRecorder } from './eventRecorder';

const HOP_BY_HOP_HEADERS = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
]);

/**
 * Validates request path against dangerous path traversal attacks.
 */
function isPathTraversal(path: string): boolean {
  if (path.includes('\0')) return true;
  let decoded = path;
  try {
    decoded = decodeURIComponent(path);
  } catch {
    return true; // Malformed percent-encoding is rejected
  }
  const segments = decoded.split('/');
  return segments.some((segment) => segment === '..' || segment.includes('..'));
}

/**
 * Generates a cryptographically secure, unpredictable session ID with 192 bits of entropy.
 */
function generateSecureSessionId(): string {
  return `sess_${crypto.randomBytes(24).toString('base64url')}`;
}

/**
 * Validates session ID format to prevent session fixation, header injection, or path traversal.
 * Accepted format: 10-64 chars of alphanumeric, underscore, and hyphen.
 */
function isValidSessionId(sessionId: unknown): sessionId is string {
  if (typeof sessionId !== 'string') return false;
  const trimmed = sessionId.trim();
  if (
    trimmed.includes('..') ||
    trimmed.includes('/') ||
    trimmed.includes('\\') ||
    trimmed.includes(';') ||
    trimmed.includes(' ') ||
    trimmed.includes('<') ||
    trimmed.includes('>')
  ) {
    return false;
  }
  return /^[a-zA-Z0-9_-]{10,64}$/.test(trimmed);
}

/**
 * Derives or extracts a cryptographically secure pseudonymous session identifier.
 * Prevents session fixation by strictly validating existing session tokens,
 * and generates unpredictable 192-bit cryptographic IDs when not provided or invalid.
 * Never falls back to predictable client characteristic hashes.
 */
function extractSessionId(req: Request): { sessionId: string; isNewSession: boolean } {
  // 1. Check for deception_session cookie first (standard browser session)
  if (req.headers.cookie) {
    const match = req.headers.cookie.match(/(?:^|;\s*)deception_session=([a-zA-Z0-9_-]{10,64})/);
    if (match && isValidSessionId(match[1])) {
      return { sessionId: match[1], isNewSession: false };
    }
  }

  // 2. Check for X-Session-ID header (API / test clients)
  const clientSessionHeader = req.headers['x-session-id'];
  if (typeof clientSessionHeader === 'string') {
    const trimmed = clientSessionHeader.trim();
    if (isValidSessionId(trimmed)) {
      return { sessionId: trimmed, isNewSession: false };
    }
  }

  // 3. Fallback: Generate fresh cryptographically random session ID (no IP/UA hashing)
  return { sessionId: generateSecureSessionId(), isNewSession: true };
}

export function createProxyMiddleware(
  config: GatewayConfig,
  sessionRouter: SessionRoutingStore = defaultSessionRouter,
  metricsCollector: MetricsCollector = defaultMetricsCollector,
  eventRecorder: SecurityEventRecorder = defaultEventRecorder
) {
  const originBase = new URL(config.originUrl);
  const deceptionBase = new URL(config.deceptionServiceUrl);

  return (req: Request, res: Response, next: NextFunction): void => {
    const startTime = process.hrtime();
    const requestId =
      (req.headers['x-request-id'] as string) ||
      (res.getHeader('X-Request-ID') as string) ||
      crypto.randomUUID();
    const clientIp =
      (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || 'unknown';
    const userAgent = (req.headers['user-agent'] as string) || 'unknown';

    // Strip client-supplied routing & detection headers to prevent spoofing
    delete req.headers['x-detection-score'];
    delete req.headers['x-detection-classification'];
    delete req.headers['x-detection-error'];
    delete req.headers['x-routing-decision'];
    delete req.headers['x-routing-reason'];
    delete req.headers['x-routing-mode'];
    delete req.headers['x-routing-fallback'];

    // Extract or derive cryptographically secure pseudonymous session ID
    const { sessionId, isNewSession } = extractSessionId(req);

    // Attach HttpOnly, SameSite=Lax session cookie if new session or cookie missing
    if (!req.headers.cookie || !req.headers.cookie.includes('deception_session=')) {
      const existingSetCookie = res.getHeader('Set-Cookie');
      const sessionCookie = `deception_session=${sessionId}; Path=/; HttpOnly; SameSite=Lax`;
      if (existingSetCookie) {
        const list = Array.isArray(existingSetCookie) ? existingSetCookie : [String(existingSetCookie)];
        res.setHeader('Set-Cookie', [...list, sessionCookie]);
      } else {
        res.setHeader('Set-Cookie', [sessionCookie]);
      }
    }

    // 1. Enforce body size limit via Content-Length header if present
    const contentLengthHeader = req.headers['content-length'];
    if (contentLengthHeader) {
      const contentLength = parseInt(contentLengthHeader, 10);
      if (!isNaN(contentLength) && contentLength > config.maxRequestBodySize) {
        const duration = process.hrtime(startTime);
        const durationMs = duration[0] * 1000 + duration[1] / 1e6;
        logRequest({
          timestamp: new Date().toISOString(),
          requestId,
          method: req.method,
          path: req.originalUrl,
          statusCode: 413,
          durationMs,
          clientIp,
          userAgent,
          sessionId,
          error: 'Payload Too Large (Content-Length exceeded limit)',
        });

        res.status(413).json({
          error: 'Payload Too Large',
          message: `Request body exceeds size limit of ${config.maxRequestBodySize} bytes.`,
          requestId,
        });
        return;
      }
    }

    // 2. Reject path traversal attempts
    if (req.path.includes('/../') || req.path.endsWith('/..') || isPathTraversal(req.path)) {
      const duration = process.hrtime(startTime);
      const durationMs = duration[0] * 1000 + duration[1] / 1e6;
      logRequest({
        timestamp: new Date().toISOString(),
        requestId,
        method: req.method,
        path: req.originalUrl,
        statusCode: 400,
        durationMs,
        clientIp,
        userAgent,
        sessionId,
        error: 'Path Traversal detected',
      });

      res.status(400).json({
        error: 'Bad Request',
        message: 'Invalid path format.',
        requestId,
      });
      return;
    }

    // 3. Buffer and validate request body stream against maxRequestBodySize
    const bodyChunks: Buffer[] = [];
    let receivedBytes = 0;
    let payloadTooLarge = false;

    req.on('data', (chunk: Buffer) => {
      receivedBytes += chunk.length;
      if (receivedBytes > config.maxRequestBodySize) {
        payloadTooLarge = true;
        req.pause();
      } else {
        bodyChunks.push(chunk);
      }
    });

    req.on('end', async () => {
      if (payloadTooLarge) {
        const duration = process.hrtime(startTime);
        const durationMs = duration[0] * 1000 + duration[1] / 1e6;
        logRequest({
          timestamp: new Date().toISOString(),
          requestId,
          method: req.method,
          path: req.originalUrl,
          statusCode: 413,
          durationMs,
          clientIp,
          userAgent,
          sessionId,
          error: 'Payload Too Large (Streamed body exceeded limit)',
        });

        res.status(413).json({
          error: 'Payload Too Large',
          message: `Request body exceeds size limit of ${config.maxRequestBodySize} bytes.`,
          requestId,
        });
        return;
      }

      const requestBody = Buffer.concat(bodyChunks);

      // 4. Feature Extraction & Asynchronous ML Detection
      const features = extractFeatures(req, requestId, requestBody.length);
      const detectionResult: DetectionScoreResult = await queryDetectionEngine(features, config);

      // 5. Policy Decision Evaluation (Stage 5 Decision Controller)
      const hasExistingDeception = sessionRouter.isSessionAssignedToDeception(sessionId);
      const decision: ControllerDecision = evaluateRoutingPolicy({
        riskScore: detectionResult.riskScore,
        classification: detectionResult.classification,
        evidence: detectionResult.evidence,
        sessionId,
        hasExistingDeceptionAssignment: hasExistingDeception,
        routingMode: config.routingMode,
        emergencyDisableDiversion: config.emergencyDisableDiversion,
        deceptionScoreThreshold: config.deceptionScoreThreshold,
      });

      // Maintain sticky session assignment in store if diverted to deception
      if (decision.target === 'DECEPTION' && !hasExistingDeception) {
        sessionRouter.assignSessionToDeception(
          sessionId,
          decision.reason,
          detectionResult.riskScore
        );
      }

      // Attach detection & routing outcome headers to client response
      res.setHeader('X-Request-ID', requestId);
      res.setHeader('X-Session-ID', sessionId);
      res.setHeader('X-Detection-Score', detectionResult.riskScore.toFixed(4));
      res.setHeader('X-Detection-Classification', detectionResult.classification);
      res.setHeader('X-Routing-Decision', decision.target);
      res.setHeader('X-Routing-Reason', decision.reason);
      res.setHeader('X-Routing-Mode', config.routingMode);
      if (detectionResult.error) {
        res.setHeader('X-Detection-Error', detectionResult.error);
      }

      // 6. Upstream Proxy Request Execution with Safe Fallback
      const isDeceptionTarget = decision.target === 'DECEPTION';
      const initialTargetBase = isDeceptionTarget ? config.deceptionServiceUrl : config.originUrl;

      function executeProxyRequest(targetBaseUrl: string, isDeceptionAttempt: boolean) {
        const targetBase = new URL(targetBaseUrl);
        const isHttps = targetBase.protocol === 'https:';
        const transport = isHttps ? https : http;

        // Construct destination URL - client headers never override target
        const targetUrl = new URL(req.originalUrl, targetBaseUrl);

        // Strict validation: target URL origin must match authorized target origin exactly
        if (targetUrl.origin !== targetBase.origin) {
          res.status(400).json({
            error: 'Bad Request',
            message: 'Invalid destination URL.',
            requestId,
          });
          return;
        }

        // Prepare outgoing headers
        const outgoingHeaders: http.OutgoingHttpHeaders = {};
        for (const [key, value] of Object.entries(req.headers)) {
          const lower = key.toLowerCase();
          if (!HOP_BY_HOP_HEADERS.has(lower) && lower !== 'host') {
            outgoingHeaders[key] = value;
          }
        }

        // Set Host header strictly to upstream host
        outgoingHeaders['host'] = targetBase.host;
        outgoingHeaders['x-request-id'] = requestId;
        outgoingHeaders['x-session-id'] = sessionId;

        const existingXff = req.headers['x-forwarded-for'];
        outgoingHeaders['x-forwarded-for'] = existingXff
          ? `${existingXff}, ${clientIp}`
          : clientIp;
        outgoingHeaders['x-forwarded-proto'] = req.protocol;

        if (requestBody.length > 0) {
          outgoingHeaders['content-length'] = requestBody.length;
        }

        let isTimedOut = false;
        const proxyReq = transport.request(
          {
            protocol: targetUrl.protocol,
            hostname: targetUrl.hostname,
            port: targetUrl.port || (isHttps ? 443 : 80),
            path: `${targetUrl.pathname}${targetUrl.search}`,
            method: req.method,
            headers: outgoingHeaders,
            timeout: config.proxyTimeoutMs,
          },
          (upstreamRes) => {
            const statusCode = upstreamRes.statusCode || 200;
            res.status(statusCode);

            for (let i = 0; i < upstreamRes.rawHeaders.length; i += 2) {
              const headerName = upstreamRes.rawHeaders[i];
              const headerValue = upstreamRes.rawHeaders[i + 1];
              const lowerName = headerName.toLowerCase();

              if (!HOP_BY_HOP_HEADERS.has(lowerName)) {
                if (lowerName === 'set-cookie') {
                  const existing = res.getHeader('Set-Cookie');
                  if (existing) {
                    const cookies = Array.isArray(existing) ? existing : [String(existing)];
                    res.setHeader('Set-Cookie', [...cookies, headerValue]);
                  } else {
                    res.setHeader('Set-Cookie', headerValue);
                  }
                } else {
                  res.setHeader(headerName, headerValue);
                }
              }
            }

            // Always ensure tracking headers are preserved
            res.setHeader('X-Request-ID', requestId);
            res.setHeader('X-Session-ID', sessionId);

            upstreamRes.pipe(res);

            upstreamRes.on('end', () => {
              const duration = process.hrtime(startTime);
              const durationMs = duration[0] * 1000 + duration[1] / 1e6;
              const finalDecision =
                (res.getHeader('X-Routing-Decision') as string) || decision.target;

              logRequest({
                timestamp: new Date().toISOString(),
                requestId,
                method: req.method,
                path: req.originalUrl,
                statusCode,
                durationMs,
                clientIp,
                userAgent,
                sessionId,
                routingDecision: finalDecision,
                routingReason: decision.reason,
                routingMode: config.routingMode,
                targetOrigin: targetBase.origin,
                detectionScore: detectionResult.riskScore,
                detectionClassification: detectionResult.classification,
                detectionInferenceMs: detectionResult.inferenceDurationMs,
                ...(detectionResult.error ? { detectionError: detectionResult.error } : {}),
              });

              // Operational metrics recording
              metricsCollector.recordRequest({
                durationMs,
                statusCode,
                routingDecision: finalDecision,
                detectionScore: detectionResult.riskScore,
                detectionLatencyMs: detectionResult.inferenceDurationMs,
                detectionError: detectionResult.error,
                isDeceptionTarget: isDeceptionAttempt,
                deceptionLatencyMs: isDeceptionAttempt ? durationMs : undefined,
                isQuarantined: false,
              });

              // Unified security event dispatch
              eventRecorder.recordEvent(
                {
                  requestId,
                  sessionId,
                  timestamp: new Date().toISOString(),
                  method: req.method,
                  path: sanitizePath(req.originalUrl),
                  statusCode,
                  durationMs,
                  detectionScore: detectionResult.riskScore,
                  detectionClassification: detectionResult.classification,
                  detectionLatencyMs: detectionResult.inferenceDurationMs,
                  routingDecision: finalDecision,
                  routingReason: decision.reason,
                  routingMode: config.routingMode,
                  failureQuarantined: false,
                  clientIp,
                },
                config
              );
            });
          }
        );

        proxyReq.on('timeout', () => {
          isTimedOut = true;
          proxyReq.destroy(new Error('ProxyTimeout'));

          // Check if deception failure should be quarantined to prevent origin exposure
          if (isDeceptionAttempt && !res.headersSent) {
            const shouldQuarantine =
              hasExistingDeception || config.deceptionFailurePolicy === 'quarantine';

            if (shouldQuarantine) {
              console.warn(
                `[Gateway-Routing] Deception runtime timed out for request ${requestId}. Deception session quarantined to prevent origin exposure.`
              );
              const duration = process.hrtime(startTime);
              const durationMs = duration[0] * 1000 + duration[1] / 1e6;
              logRequest({
                timestamp: new Date().toISOString(),
                requestId,
                method: req.method,
                path: req.originalUrl,
                statusCode: 503,
                durationMs,
                clientIp,
                userAgent,
                sessionId,
                routingDecision: 'DECEPTION',
                routingReason: 'DECEPTION_UNAVAILABLE_QUARANTINED',
                routingMode: config.routingMode,
                targetOrigin: targetBase.origin,
                error: 'Deception runtime timed out; quarantined',
                detectionScore: detectionResult.riskScore,
                detectionClassification: detectionResult.classification,
              });

              metricsCollector.recordRequest({
                durationMs,
                statusCode: 503,
                routingDecision: 'DECEPTION',
                detectionScore: detectionResult.riskScore,
                detectionLatencyMs: detectionResult.inferenceDurationMs,
                isDeceptionTarget: true,
                deceptionLatencyMs: durationMs,
                deceptionError: 'Deception runtime timed out; quarantined',
                isQuarantined: true,
              });

              eventRecorder.recordEvent(
                {
                  requestId,
                  sessionId,
                  timestamp: new Date().toISOString(),
                  method: req.method,
                  path: sanitizePath(req.originalUrl),
                  statusCode: 503,
                  durationMs,
                  detectionScore: detectionResult.riskScore,
                  detectionClassification: detectionResult.classification,
                  detectionLatencyMs: detectionResult.inferenceDurationMs,
                  routingDecision: 'DECEPTION',
                  routingReason: 'DECEPTION_UNAVAILABLE_QUARANTINED',
                  routingMode: config.routingMode,
                  failureQuarantined: true,
                  clientIp,
                },
                config
              );

              res.setHeader('X-Routing-Fallback', 'quarantined');
              res.setHeader('X-Routing-Decision', 'DECEPTION');
              res.setHeader('X-Routing-Reason', 'DECEPTION_UNAVAILABLE_QUARANTINED');
              res.status(503).json({
                error: 'Service Unavailable',
                message:
                  'Security runtime unavailable. Deception session quarantined to prevent origin exposure.',
                requestId,
              });
              return;
            }

            console.warn(
              `[Gateway-Routing] Deception runtime timed out for request ${requestId}. Executing safe fallback to origin.`
            );
            res.setHeader('X-Routing-Fallback', 'deception-unavailable');
            res.setHeader('X-Routing-Decision', 'ORIGIN');
            executeProxyRequest(config.originUrl, false);
            return;
          }

          if (!res.headersSent) {
            const duration = process.hrtime(startTime);
            const durationMs = duration[0] * 1000 + duration[1] / 1e6;
            logRequest({
              timestamp: new Date().toISOString(),
              requestId,
              method: req.method,
              path: req.originalUrl,
              statusCode: 504,
              durationMs,
              clientIp,
              userAgent,
              sessionId,
              routingDecision: 'ORIGIN',
              routingReason: 'UPSTREAM_TIMEOUT',
              routingMode: config.routingMode,
              targetOrigin: targetBase.origin,
              error: 'Upstream service timed out',
              detectionScore: detectionResult.riskScore,
              detectionClassification: detectionResult.classification,
            });

            metricsCollector.recordRequest({
              durationMs,
              statusCode: 504,
              routingDecision: 'ORIGIN',
              detectionScore: detectionResult.riskScore,
              detectionLatencyMs: detectionResult.inferenceDurationMs,
            });

            eventRecorder.recordEvent(
              {
                requestId,
                sessionId,
                timestamp: new Date().toISOString(),
                method: req.method,
                path: sanitizePath(req.originalUrl),
                statusCode: 504,
                durationMs,
                detectionScore: detectionResult.riskScore,
                detectionClassification: detectionResult.classification,
                detectionLatencyMs: detectionResult.inferenceDurationMs,
                routingDecision: 'ORIGIN',
                routingReason: 'UPSTREAM_TIMEOUT',
                routingMode: config.routingMode,
                failureQuarantined: false,
                clientIp,
              },
              config
            );

            res.status(504).json({
              error: 'Gateway Timeout',
              message: 'Upstream origin service timed out.',
              requestId,
            });
          }
        });

        proxyReq.on('error', (err: any) => {
          if (isTimedOut || res.headersSent) return;

          // Check if deception failure should be quarantined to prevent origin exposure
          if (isDeceptionAttempt) {
            const shouldQuarantine =
              hasExistingDeception || config.deceptionFailurePolicy === 'quarantine';

            if (shouldQuarantine) {
              console.warn(
                `[Gateway-Routing] Deception runtime unavailable (${err.code || err.message}) for request ${requestId}. Deception session quarantined to prevent origin exposure.`
              );
              const duration = process.hrtime(startTime);
              const durationMs = duration[0] * 1000 + duration[1] / 1e6;
              logRequest({
                timestamp: new Date().toISOString(),
                requestId,
                method: req.method,
                path: req.originalUrl,
                statusCode: 503,
                durationMs,
                clientIp,
                userAgent,
                sessionId,
                routingDecision: 'DECEPTION',
                routingReason: 'DECEPTION_UNAVAILABLE_QUARANTINED',
                routingMode: config.routingMode,
                targetOrigin: targetBase.origin,
                error: `Deception runtime unavailable: ${err.code || err.message}; quarantined`,
                detectionScore: detectionResult.riskScore,
                detectionClassification: detectionResult.classification,
              });

              metricsCollector.recordRequest({
                durationMs,
                statusCode: 503,
                routingDecision: 'DECEPTION',
                detectionScore: detectionResult.riskScore,
                detectionLatencyMs: detectionResult.inferenceDurationMs,
                isDeceptionTarget: true,
                deceptionLatencyMs: durationMs,
                deceptionError: `Deception runtime unavailable: ${err.code || err.message}; quarantined`,
                isQuarantined: true,
              });

              eventRecorder.recordEvent(
                {
                  requestId,
                  sessionId,
                  timestamp: new Date().toISOString(),
                  method: req.method,
                  path: sanitizePath(req.originalUrl),
                  statusCode: 503,
                  durationMs,
                  detectionScore: detectionResult.riskScore,
                  detectionClassification: detectionResult.classification,
                  detectionLatencyMs: detectionResult.inferenceDurationMs,
                  routingDecision: 'DECEPTION',
                  routingReason: 'DECEPTION_UNAVAILABLE_QUARANTINED',
                  routingMode: config.routingMode,
                  failureQuarantined: true,
                  clientIp,
                },
                config
              );

              res.setHeader('X-Routing-Fallback', 'quarantined');
              res.setHeader('X-Routing-Decision', 'DECEPTION');
              res.setHeader('X-Routing-Reason', 'DECEPTION_UNAVAILABLE_QUARANTINED');
              res.status(503).json({
                error: 'Service Unavailable',
                message:
                  'Security runtime unavailable. Deception session quarantined to prevent origin exposure.',
                requestId,
              });
              return;
            }

            console.warn(
              `[Gateway-Routing] Deception runtime unavailable (${err.code || err.message}) for request ${requestId}. Executing safe fallback to origin.`
            );
            res.setHeader('X-Routing-Fallback', 'deception-unavailable');
            res.setHeader('X-Routing-Decision', 'ORIGIN');
            executeProxyRequest(config.originUrl, false);
            return;
          }

          const duration = process.hrtime(startTime);
          const durationMs = duration[0] * 1000 + duration[1] / 1e6;
          logRequest({
            timestamp: new Date().toISOString(),
            requestId,
            method: req.method,
            path: req.originalUrl,
            statusCode: 502,
            durationMs,
            clientIp,
            userAgent,
            sessionId,
            routingDecision: 'ORIGIN',
            routingReason: 'UPSTREAM_ERROR',
            routingMode: config.routingMode,
            targetOrigin: targetBase.origin,
            error: `Upstream service error: ${err.code || err.message}`,
            detectionScore: detectionResult.riskScore,
            detectionClassification: detectionResult.classification,
          });

          metricsCollector.recordRequest({
            durationMs,
            statusCode: 502,
            routingDecision: 'ORIGIN',
            detectionScore: detectionResult.riskScore,
            detectionLatencyMs: detectionResult.inferenceDurationMs,
          });

          eventRecorder.recordEvent(
            {
              requestId,
              sessionId,
              timestamp: new Date().toISOString(),
              method: req.method,
              path: sanitizePath(req.originalUrl),
              statusCode: 502,
              durationMs,
              detectionScore: detectionResult.riskScore,
              detectionClassification: detectionResult.classification,
              detectionLatencyMs: detectionResult.inferenceDurationMs,
              routingDecision: 'ORIGIN',
              routingReason: 'UPSTREAM_ERROR',
              routingMode: config.routingMode,
              failureQuarantined: false,
              clientIp,
            },
            config
          );

          res.status(502).json({
            error: 'Bad Gateway',
            message: 'Upstream origin service is unavailable.',
            requestId,
          });
        });

        if (requestBody.length > 0) {
          proxyReq.write(requestBody);
        }
        proxyReq.end();
      }

      executeProxyRequest(initialTargetBase, isDeceptionTarget);
    });

    req.on('error', (_err) => {
      if (!res.headersSent) {
        res.status(400).json({
          error: 'Bad Request',
          message: 'Error reading request body.',
          requestId,
        });
      }
    });
  };
}
