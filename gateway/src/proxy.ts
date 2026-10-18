import http from 'node:http';
import https from 'node:https';
import { Request, Response, NextFunction } from 'express';
import { GatewayConfig } from './config';
import { logRequest } from './logger';
import { extractFeatures } from './features';
import { queryDetectionEngine, DetectionScoreResult } from './detector';

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

export function createProxyMiddleware(config: GatewayConfig) {
  const originBase = new URL(config.originUrl);
  const isHttps = originBase.protocol === 'https:';
  const transport = isHttps ? https : http;

  return (req: Request, res: Response, next: NextFunction): void => {
    const startTime = process.hrtime();
    const requestId = (req.headers['x-request-id'] as string) || (res.getHeader('X-Request-ID') as string);
    const clientIp = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || 'unknown';
    const userAgent = (req.headers['user-agent'] as string) || 'unknown';

    // Strip client-supplied detection headers to prevent spoofing
    delete req.headers['x-detection-score'];
    delete req.headers['x-detection-classification'];
    delete req.headers['x-detection-error'];

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

    // 2. Normalize and construct destination URL strictly against authorized origin
    // Reject path traversal attempts that attempt to climb directory hierarchies
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
        error: 'Path Traversal detected',
      });

      res.status(400).json({
        error: 'Bad Request',
        message: 'Invalid path format.',
        requestId,
      });
      return;
    }

    // Construct destination URL - client headers (Host, X-Forwarded-Host, etc.) NEVER override origin
    const targetUrl = new URL(req.originalUrl, config.originUrl);

    // Strict validation: target URL origin must match authorized origin exactly
    if (targetUrl.origin !== config.originUrl) {
      res.status(400).json({
        error: 'Bad Request',
        message: 'Invalid destination URL.',
        requestId,
      });
      return;
    }

    // 3. Prepare outgoing headers
    const outgoingHeaders: http.OutgoingHttpHeaders = {};
    for (const [key, value] of Object.entries(req.headers)) {
      const lower = key.toLowerCase();
      if (!HOP_BY_HOP_HEADERS.has(lower) && lower !== 'host') {
        outgoingHeaders[key] = value;
      }
    }

    // Set Host header strictly to upstream origin host
    outgoingHeaders['host'] = originBase.host;

    // Propagate request ID
    outgoingHeaders['x-request-id'] = requestId;

    // Forwarding client IP metadata
    const existingXff = req.headers['x-forwarded-for'];
    outgoingHeaders['x-forwarded-for'] = existingXff ? `${existingXff}, ${clientIp}` : clientIp;
    outgoingHeaders['x-forwarded-proto'] = req.protocol;

    // 4. Buffer and validate request body stream against maxRequestBodySize
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
      if (requestBody.length > 0) {
        outgoingHeaders['content-length'] = requestBody.length;
      }

      // 5. Stage 3 Feature Extraction & Asynchronous ML Detection (Shadow Mode)
      const features = extractFeatures(req, requestId, requestBody.length);
      const detectionResult: DetectionScoreResult = await queryDetectionEngine(features, config);

      // Attach detection outcome headers to client response (for verification & observability)
      res.setHeader('X-Detection-Score', detectionResult.riskScore.toFixed(4));
      res.setHeader('X-Detection-Classification', detectionResult.classification);
      if (detectionResult.error) {
        res.setHeader('X-Detection-Error', detectionResult.error);
      }

      // 6. SHADOW MODE: Forward request to authorized test-origin regardless of detection result
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
        (originRes) => {
          // Preserve origin HTTP status
          const statusCode = originRes.statusCode || 200;
          res.status(statusCode);

          // Preserve legitimate origin headers and multiple cookies
          for (let i = 0; i < originRes.rawHeaders.length; i += 2) {
            const headerName = originRes.rawHeaders[i];
            const headerValue = originRes.rawHeaders[i + 1];
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

          // Always ensure X-Request-ID and Detection metadata are preserved
          res.setHeader('X-Request-ID', requestId);

          // Pipe origin response back to client
          originRes.pipe(res);

          originRes.on('end', () => {
            const duration = process.hrtime(startTime);
            const durationMs = duration[0] * 1000 + duration[1] / 1e6;
            logRequest({
              timestamp: new Date().toISOString(),
              requestId,
              method: req.method,
              path: req.originalUrl,
              statusCode,
              durationMs,
              clientIp,
              userAgent,
              detectionScore: detectionResult.riskScore,
              detectionClassification: detectionResult.classification,
              detectionInferenceMs: detectionResult.inferenceDurationMs,
              ...(detectionResult.error ? { detectionError: detectionResult.error } : {}),
            });
          });
        }
      );

      // Handle origin timeout
      proxyReq.on('timeout', () => {
        isTimedOut = true;
        proxyReq.destroy(new Error('ProxyTimeout'));

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
            error: 'Upstream origin timed out',
            detectionScore: detectionResult.riskScore,
            detectionClassification: detectionResult.classification,
          });

          res.status(504).json({
            error: 'Gateway Timeout',
            message: 'Upstream origin service timed out.',
            requestId,
          });
        }
      });

      // Handle connection errors (e.g., origin offline / connection refused)
      proxyReq.on('error', (err: any) => {
        if (isTimedOut || res.headersSent) return;

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
          error: `Upstream origin error: ${err.code || err.message}`,
          detectionScore: detectionResult.riskScore,
          detectionClassification: detectionResult.classification,
        });

        res.status(502).json({
          error: 'Bad Gateway',
          message: 'Upstream origin service is unavailable.',
          requestId,
        });
      });

      // Send buffered body
      if (requestBody.length > 0) {
        proxyReq.write(requestBody);
      }
      proxyReq.end();
    });

    req.on('error', (err) => {
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
