/**
 * High-performance Operational Metrics Collector for Gateway.
 * Tracks throughput, routing breakdown, HTTP status distributions,
 * detection & deception health, and latency percentiles (p50, p95).
 */

export interface LatencyPercentiles {
  p50Ms: number;
  p95Ms: number;
  minMs: number;
  maxMs: number;
  avgMs: number;
}

export interface GatewayMetricsSummary {
  service: string;
  timestamp: string;
  uptimeSeconds: number;
  totalRequests: number;
  routingBreakdown: {
    ORIGIN: number;
    DECEPTION: number;
    OBSERVE_ONLY: number;
  };
  statusCodes: Record<string, number>;
  quarantinedRequests: number;
  activeDeceptionSessions: number;
  emergencyDisableActive: boolean;
  routingMode: string;
  gatewayLatency: LatencyPercentiles;
  detection: {
    calls: number;
    errors: number;
    availabilityPct: number;
    latency: LatencyPercentiles;
  };
  deception: {
    calls: number;
    errors: number;
    quarantined: number;
    latency: LatencyPercentiles;
  };
}

export class MetricsCollector {
  private totalRequests = 0;
  private decisions: { ORIGIN: number; DECEPTION: number; OBSERVE_ONLY: number } = {
    ORIGIN: 0,
    DECEPTION: 0,
    OBSERVE_ONLY: 0,
  };
  private statusCodes: Record<string, number> = {};
  private quarantinedCount = 0;

  // Detection metrics
  private detectionCalls = 0;
  private detectionErrors = 0;
  private detectionLatencies: number[] = [];

  // Deception metrics
  private deceptionCalls = 0;
  private deceptionErrors = 0;
  private deceptionLatencies: number[] = [];

  // Gateway end-to-end latencies
  private gatewayLatencies: number[] = [];

  private readonly maxBufferSize = 2000;
  private readonly startTime = Date.now();

  private pushBounded(arr: number[], val: number): void {
    if (typeof val !== 'number' || isNaN(val) || val < 0) return;
    if (arr.length >= this.maxBufferSize) {
      arr.shift();
    }
    arr.push(val);
  }

  private computePercentiles(values: number[]): LatencyPercentiles {
    if (values.length === 0) {
      return { p50Ms: 0, p95Ms: 0, minMs: 0, maxMs: 0, avgMs: 0 };
    }

    const sorted = [...values].sort((a, b) => a - b);
    const minMs = parseFloat(sorted[0].toFixed(2));
    const maxMs = parseFloat(sorted[sorted.length - 1].toFixed(2));
    const sum = sorted.reduce((acc, v) => acc + v, 0);
    const avgMs = parseFloat((sum / sorted.length).toFixed(2));

    const p50Index = Math.min(Math.floor(sorted.length * 0.5), sorted.length - 1);
    const p95Index = Math.min(Math.floor(sorted.length * 0.95), sorted.length - 1);

    const p50Ms = parseFloat(sorted[p50Index].toFixed(2));
    const p95Ms = parseFloat(sorted[p95Index].toFixed(2));

    return { p50Ms, p95Ms, minMs, maxMs, avgMs };
  }

  public recordRequest(params: {
    durationMs: number;
    statusCode: number;
    routingDecision: 'ORIGIN' | 'DECEPTION' | 'OBSERVE_ONLY' | string;
    detectionScore?: number;
    detectionLatencyMs?: number;
    detectionError?: string;
    isDeceptionTarget?: boolean;
    deceptionLatencyMs?: number;
    deceptionError?: string;
    isQuarantined?: boolean;
  }): void {
    this.totalRequests++;

    // Decision counters
    if (params.routingDecision === 'DECEPTION') {
      this.decisions.DECEPTION++;
    } else if (params.routingDecision === 'OBSERVE_ONLY') {
      this.decisions.OBSERVE_ONLY++;
    } else {
      this.decisions.ORIGIN++;
    }

    // Status code breakdown
    const codeKey = String(params.statusCode || 200);
    this.statusCodes[codeKey] = (this.statusCodes[codeKey] || 0) + 1;

    // Quarantine tracking
    if (params.isQuarantined) {
      this.quarantinedCount++;
    }

    // Gateway latency
    this.pushBounded(this.gatewayLatencies, params.durationMs);

    // Detection telemetry
    if (params.detectionLatencyMs !== undefined || params.detectionScore !== undefined) {
      this.detectionCalls++;
      if (params.detectionLatencyMs !== undefined) {
        this.pushBounded(this.detectionLatencies, params.detectionLatencyMs);
      }
      if (params.detectionError) {
        this.detectionErrors++;
      }
    }

    // Deception telemetry
    if (params.isDeceptionTarget) {
      this.deceptionCalls++;
      if (params.deceptionLatencyMs !== undefined) {
        this.pushBounded(this.deceptionLatencies, params.deceptionLatencyMs);
      }
      if (params.deceptionError) {
        this.deceptionErrors++;
      }
    }
  }

  public getSummary(
    activeDeceptionSessions: number = 0,
    emergencyDisableActive: boolean = false,
    routingMode: string = 'shadow'
  ): GatewayMetricsSummary {
    const uptimeSeconds = parseFloat(((Date.now() - this.startTime) / 1000).toFixed(1));
    const availabilityPct =
      this.detectionCalls > 0
        ? parseFloat(
            (((this.detectionCalls - this.detectionErrors) / this.detectionCalls) * 100).toFixed(1)
          )
        : 100.0;

    return {
      service: 'gateway',
      timestamp: new Date().toISOString(),
      uptimeSeconds,
      totalRequests: this.totalRequests,
      routingBreakdown: { ...this.decisions },
      statusCodes: { ...this.statusCodes },
      quarantinedRequests: this.quarantinedCount,
      activeDeceptionSessions,
      emergencyDisableActive,
      routingMode,
      gatewayLatency: this.computePercentiles(this.gatewayLatencies),
      detection: {
        calls: this.detectionCalls,
        errors: this.detectionErrors,
        availabilityPct,
        latency: this.computePercentiles(this.detectionLatencies),
      },
      deception: {
        calls: this.deceptionCalls,
        errors: this.deceptionErrors,
        quarantined: this.quarantinedCount,
        latency: this.computePercentiles(this.deceptionLatencies),
      },
    };
  }

  public reset(): void {
    this.totalRequests = 0;
    this.decisions = { ORIGIN: 0, DECEPTION: 0, OBSERVE_ONLY: 0 };
    this.statusCodes = {};
    this.quarantinedCount = 0;
    this.detectionCalls = 0;
    this.detectionErrors = 0;
    this.detectionLatencies = [];
    this.deceptionCalls = 0;
    this.deceptionErrors = 0;
    this.deceptionLatencies = [];
    this.gatewayLatencies = [];
  }
}

export const defaultMetricsCollector = new MetricsCollector();
