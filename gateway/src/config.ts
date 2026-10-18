import dotenv from 'dotenv';

dotenv.config();

export interface GatewayConfig {
  port: number;
  host: string;
  originUrl: string;
  allowedOrigins: string[];
  proxyTimeoutMs: number;
  maxRequestBodySize: number; // in bytes
  detectionServiceUrl: string;
  detectionTimeoutMs: number;
  detectionEnabled: boolean;
}

const DEFAULT_ALLOWED_ORIGINS = [
  'http://test-origin:5000',
  'http://localhost:5000',
  'http://127.0.0.1:5000',
];

export function validateOriginUrl(rawUrl: string, allowedOrigins: string[]): URL {
  if (!rawUrl || typeof rawUrl !== 'string') {
    throw new Error('ORIGIN_URL environment variable is required.');
  }

  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch (err) {
    throw new Error(`Invalid ORIGIN_URL format: "${rawUrl}". Must be a valid HTTP/HTTPS URL.`);
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error(`Invalid ORIGIN_URL protocol "${parsed.protocol}". Only http: and https: are supported.`);
  }

  // Normalize allowed origins
  const normalizedAllowed = allowedOrigins.map((o) => {
    try {
      return new URL(o).origin;
    } catch {
      return o.trim();
    }
  });

  if (!normalizedAllowed.includes(parsed.origin)) {
    throw new Error(
      `Forbidden ORIGIN_URL "${parsed.origin}". Allowed origins in Stage 2/3: [${normalizedAllowed.join(', ')}]`
    );
  }

  return parsed;
}

export function getConfig(): GatewayConfig {
  const port = parseInt(process.env.PORT || '8080', 10);
  const host = process.env.HOST || '0.0.0.0';
  const proxyTimeoutMs = parseInt(process.env.PROXY_TIMEOUT_MS || '5000', 10);
  const maxRequestBodySize = parseInt(process.env.MAX_REQUEST_BODY_SIZE || '1048576', 10); // 1MB default

  const rawAllowedOrigins = process.env.ALLOWED_ORIGINS
    ? process.env.ALLOWED_ORIGINS.split(',').map((s) => s.trim()).filter(Boolean)
    : DEFAULT_ALLOWED_ORIGINS;

  const rawOriginUrl = process.env.ORIGIN_URL || 'http://test-origin:5000';
  const validatedOrigin = validateOriginUrl(rawOriginUrl, rawAllowedOrigins);

  const detectionServiceUrl = process.env.DETECTION_SERVICE_URL || 'http://detection:8000';
  const detectionTimeoutMs = parseInt(process.env.DETECTION_TIMEOUT_MS || '500', 10);
  const detectionEnabled = process.env.DETECTION_ENABLED !== 'false';

  return {
    port,
    host,
    originUrl: validatedOrigin.origin,
    allowedOrigins: rawAllowedOrigins,
    proxyTimeoutMs,
    maxRequestBodySize,
    detectionServiceUrl,
    detectionTimeoutMs,
    detectionEnabled,
  };
}
