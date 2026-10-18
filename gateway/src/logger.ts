export interface RequestLogMetadata {
  timestamp: string;
  requestId: string;
  method: string;
  path: string;
  statusCode: number;
  durationMs: number;
  clientIp?: string;
  userAgent?: string;
  error?: string;
  detectionScore?: number;
  detectionClassification?: string;
  detectionInferenceMs?: number;
  detectionError?: string;
  sessionId?: string;
  routingDecision?: string;
  routingReason?: string;
  routingMode?: string;
  targetOrigin?: string;
}

const REDACTED_HEADERS = new Set([
  'authorization',
  'proxy-authorization',
  'cookie',
  'set-cookie',
  'x-api-key',
  'api-key',
  'secret',
  'token',
]);

/**
 * Sanitizes an HTTP headers dictionary, ensuring credentials and cookies
 * are never exposed in log output.
 */
export function sanitizeHeaders(
  headers: Record<string, string | string[] | undefined>
): Record<string, string | string[]> {
  const sanitized: Record<string, string | string[]> = {};
  for (const [key, value] of Object.entries(headers)) {
    if (!value) continue;
    const lowerKey = key.toLowerCase();
    if (REDACTED_HEADERS.has(lowerKey)) {
      sanitized[key] = '[REDACTED]';
    } else {
      sanitized[key] = value;
    }
  }
  return sanitized;
}

/**
 * Formats and outputs structured JSON logs for HTTP traffic metadata.
 * Never outputs raw request bodies or sensitive headers.
 */
export function logRequest(metadata: RequestLogMetadata): void {
  const logLine = JSON.stringify({
    level: metadata.statusCode >= 500 ? 'ERROR' : 'INFO',
    timestamp: metadata.timestamp,
    requestId: metadata.requestId,
    method: metadata.method,
    path: metadata.path,
    statusCode: metadata.statusCode,
    durationMs: Math.round(metadata.durationMs * 100) / 100,
    clientIp: metadata.clientIp || 'unknown',
    userAgent: metadata.userAgent || 'unknown',
    ...(metadata.sessionId ? { sessionId: metadata.sessionId } : {}),
    ...(metadata.routingDecision ? { routingDecision: metadata.routingDecision } : {}),
    ...(metadata.routingReason ? { routingReason: metadata.routingReason } : {}),
    ...(metadata.routingMode ? { routingMode: metadata.routingMode } : {}),
    ...(metadata.targetOrigin ? { targetOrigin: metadata.targetOrigin } : {}),
    ...(metadata.detectionScore !== undefined ? { detectionScore: metadata.detectionScore } : {}),
    ...(metadata.detectionClassification ? { detectionClassification: metadata.detectionClassification } : {}),
    ...(metadata.detectionInferenceMs !== undefined ? { detectionInferenceMs: metadata.detectionInferenceMs } : {}),
    ...(metadata.detectionError ? { detectionError: metadata.detectionError } : {}),
    ...(metadata.error ? { error: metadata.error } : {}),
  });

  if (metadata.statusCode >= 500) {
    console.error(logLine);
  } else {
    console.log(logLine);
  }
}
