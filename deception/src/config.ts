import dotenv from 'dotenv';

dotenv.config();

export interface DeceptionConfig {
  port: number;
  host: string;
  nodeEnv: string;
  sessionTtlMs: number;
  maxSessions: number;
  maxRequestBodySize: number;
  requestTimeoutMs: number;
}

export function getConfig(): DeceptionConfig {
  const port = parseInt(process.env.PORT || '5050', 10);
  const host = process.env.HOST || '0.0.0.0';
  const nodeEnv = process.env.NODE_ENV || 'production';
  const sessionTtlMs = parseInt(process.env.SESSION_TTL_MS || '1800000', 10); // 30 minutes
  const maxSessions = parseInt(process.env.MAX_SESSIONS || '1000', 10);
  const maxRequestBodySize = parseInt(process.env.MAX_REQUEST_BODY_SIZE || '1048576', 10); // 1MB
  const requestTimeoutMs = parseInt(process.env.REQUEST_TIMEOUT_MS || '5000', 10);

  return {
    port,
    host,
    nodeEnv,
    sessionTtlMs,
    maxSessions,
    maxRequestBodySize,
    requestTimeoutMs,
  };
}
