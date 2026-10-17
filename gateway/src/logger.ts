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
  // Output clean, structured single-line JSON log
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
    ...(metadata.error ? { error: metadata.error } : {}),
  });

  if (metadata.statusCode >= 500) {
    console.error(logLine);
  } else {
    console.log(logLine);
  }
}
