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

/**
 * Masks session identifiers so unpredictable session tokens are not leaked into routine logs.
 */
export function maskSessionId(sessionId?: string): string | undefined {
  if (!sessionId) return undefined;
  if (sessionId.length <= 8) return 'sess_***';
  return `${sessionId.slice(0, 6)}...[REDACTED]`;
}

/**
 * Sanitizes URLs/paths to redact sensitive query parameters (credentials, API keys, tokens).
 */
export function sanitizePath(pathStr: string): string {
  if (!pathStr || !pathStr.includes('?')) return pathStr;
  try {
    const [base, query] = pathStr.split('?');
    const params = new URLSearchParams(query);
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

/**
 * Formats and outputs structured JSON logs for HTTP traffic metadata.
 * Never outputs raw request bodies, credentials, unmasked session IDs, or sensitive query params.
 */
export function logRequest(metadata: RequestLogMetadata): void {
  const logLine = JSON.stringify({
    level: metadata.statusCode >= 500 ? 'ERROR' : 'INFO',
    timestamp: metadata.timestamp,
    requestId: metadata.requestId,
    method: metadata.method,
    path: sanitizePath(metadata.path),
    statusCode: metadata.statusCode,
    durationMs: Math.round(metadata.durationMs * 100) / 100,
    clientIp: metadata.clientIp || 'unknown',
    userAgent: metadata.userAgent || 'unknown',
    ...(metadata.sessionId ? { sessionId: maskSessionId(metadata.sessionId) } : {}),
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
