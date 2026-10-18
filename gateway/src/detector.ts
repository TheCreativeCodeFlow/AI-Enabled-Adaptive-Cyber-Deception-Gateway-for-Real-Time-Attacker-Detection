import { ExtractedFeatures } from './features';
import { GatewayConfig } from './config';

export interface DetectionScoreResult {
  success: boolean;
  riskScore: number;
  classification: string;
  confidence: number;
  evidence: string[];
  inferenceDurationMs: number;
  error?: string;
}

/**
 * Sends extracted request features to the Python ML Detection Service.
 * Implements strict bounded timeouts and fail-open resilience.
 */
export async function queryDetectionEngine(
  features: ExtractedFeatures,
  config: GatewayConfig
): Promise<DetectionScoreResult> {
  if (!config.detectionEnabled || !config.detectionServiceUrl) {
    return {
      success: true,
      riskScore: 0.0,
      classification: 'BYPASSED',
      confidence: 1.0,
      evidence: ['Detection disabled by configuration'],
      inferenceDurationMs: 0.0,
    };
  }

  const targetEndpoint = `${config.detectionServiceUrl.replace(/\/$/, '')}/score`;
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), config.detectionTimeoutMs);

  try {
    const res = await fetch(targetEndpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Request-ID': features.request_id,
      },
      body: JSON.stringify(features),
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    if (!res.ok) {
      return {
        success: false,
        riskScore: 0.0,
        classification: 'UNAVAILABLE',
        confidence: 0.0,
        evidence: [`Detection service returned HTTP ${res.status}`],
        inferenceDurationMs: 0.0,
        error: `HTTP_${res.status}`,
      };
    }

    const data: any = await res.json();
    return {
      success: true,
      riskScore: typeof data.risk_score === 'number' ? data.risk_score : 0.0,
      classification: typeof data.classification === 'string' ? data.classification : 'UNKNOWN',
      confidence: typeof data.confidence === 'number' ? data.confidence : 0.0,
      evidence: Array.isArray(data.evidence) ? data.evidence : [],
      inferenceDurationMs: typeof data.inference_duration_ms === 'number' ? data.inference_duration_ms : 0.0,
    };
  } catch (err: any) {
    clearTimeout(timeoutId);
    const isTimeout = err.name === 'AbortError';
    return {
      success: false,
      riskScore: 0.0,
      classification: 'UNAVAILABLE',
      confidence: 0.0,
      evidence: [isTimeout ? 'Detection engine timed out' : 'Detection engine unreachable'],
      inferenceDurationMs: 0.0,
      error: isTimeout ? 'TIMEOUT' : err.code || err.message || 'CONNECTION_ERROR',
    };
  }
}
