import http from 'node:http';
import https from 'node:https';
import { GatewayConfig } from './config';

export interface SecurityEventPayload {
  requestId: string;
  sessionId: string;
  organisationId?: string;
  applicationId?: string;
  timestamp: string;
  method: string;
  path: string;
  statusCode: number;
  durationMs: number;
  detectionScore?: number;
  detectionClassification?: string;
  detectionLatencyMs?: number;
  routingDecision: 'ORIGIN' | 'DECEPTION' | 'OBSERVE_ONLY' | string;
  routingReason: string;
  routingMode: 'shadow' | 'active' | string;
  deceptionNode?: string;
  deceptionStrategy?: string;
  failureQuarantined?: boolean;
  clientIp: string;
  metadata?: Record<string, any>;
}

export class SecurityEventRecorder {
  private recentEvents: SecurityEventPayload[] = [];
  private readonly maxBufferSize = 500;
  private failedDispatches = 0;

  /**
   * Records a security event locally and asynchronously forwards it to the backend ingestion API.
   */
  public recordEvent(event: SecurityEventPayload, config?: GatewayConfig): void {
    // 1. Maintain bounded in-memory buffer
    if (this.recentEvents.length >= this.maxBufferSize) {
      this.recentEvents.shift();
    }
    this.recentEvents.push(event);

    // 2. Asynchronously forward to backend if config is available
    if (config?.backendUrl) {
      this.dispatchToBackend(event, config);
    }
  }

  private dispatchToBackend(event: SecurityEventPayload, config: GatewayConfig): void {
    try {
      const url = new URL('/api/events', config.backendUrl);
      const isHttps = url.protocol === 'https:';
      const transport = isHttps ? https : http;
      const body = JSON.stringify(event);

      const req = transport.request(
        {
          protocol: url.protocol,
          hostname: url.hostname,
          port: url.port || (isHttps ? 443 : 80),
          path: url.pathname,
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(body),
            'x-service-token': config.serviceSharedSecret || 'deception-gateway-internal-service-secret',
          },
          timeout: 2000,
        },
        (res) => {
          res.resume(); // Discard response data cleanly
        }
      );

      req.on('error', (_err) => {
        this.failedDispatches++;
        // Quietly track dispatch failures without crashing or throwing
      });

      req.on('timeout', () => {
        this.failedDispatches++;
        req.destroy();
      });

      req.write(body);
      req.end();
    } catch {
      this.failedDispatches++;
    }
  }

  public getRecentEvents(limit: number = 50): SecurityEventPayload[] {
    const lim = Math.min(Math.max(limit, 1), this.maxBufferSize);
    return this.recentEvents.slice(-lim).reverse();
  }

  public getFailedDispatchCount(): number {
    return this.failedDispatches;
  }

  public clear(): void {
    this.recentEvents = [];
    this.failedDispatches = 0;
  }
}

export const defaultEventRecorder = new SecurityEventRecorder();
