export type RoutingTarget = 'ORIGIN' | 'DECEPTION' | 'OBSERVE_ONLY';

export interface ControllerInput {
  riskScore: number;
  classification: 'BENIGN' | 'SUSPICIOUS' | 'MALICIOUS' | 'UNAVAILABLE' | string;
  evidence?: string[];
  sessionId: string;
  hasExistingDeceptionAssignment: boolean;
  routingMode: 'shadow' | 'active';
  emergencyDisableDiversion: boolean;
  deceptionScoreThreshold: number;
}

export interface ControllerDecision {
  target: RoutingTarget;
  reason: string;
  policyVersion: string;
  sessionId: string;
  diverted: boolean;
}

export const CONTROLLER_POLICY_VERSION = '1.0.0-decision-controller';

/**
 * Deterministic Decision Controller.
 * Evaluates detection telemetry and session context against strict safety policies.
 * Guarantees that:
 * 1. Shadow mode NEVER diverts.
 * 2. Emergency disable immediately reverts all routing to ORIGIN.
 * 3. Unavailable / malformed detection results fall back safely to ORIGIN.
 * 4. Suspicious or uncertain scores remain on normal route in OBSERVE_ONLY mode.
 * 5. Only high-confidence multi-evidence malicious signals trigger DECEPTION in active mode.
 */
export function evaluateRoutingPolicy(input: ControllerInput): ControllerDecision {
  const {
    riskScore,
    classification,
    evidence = [],
    sessionId,
    hasExistingDeceptionAssignment,
    routingMode,
    emergencyDisableDiversion,
    deceptionScoreThreshold,
  } = input;

  // 1. Emergency Killswitch: Instantly aborts any diversion and forces normal route
  if (emergencyDisableDiversion) {
    return {
      target: 'ORIGIN',
      reason: 'EMERGENCY_DISABLE_ACTIVE',
      policyVersion: CONTROLLER_POLICY_VERSION,
      sessionId,
      diverted: false,
    };
  }

  // 2. Default Safety Invariant: Shadow Mode NEVER diverts traffic
  if (routingMode !== 'active') {
    return {
      target: 'ORIGIN',
      reason: 'SHADOW_MODE_ACTIVE',
      policyVersion: CONTROLLER_POLICY_VERSION,
      sessionId,
      diverted: false,
    };
  }

  // 3. Session Stickiness: Maintain deception continuity for already diverted sessions
  if (hasExistingDeceptionAssignment) {
    return {
      target: 'DECEPTION',
      reason: 'STICKY_SESSION_ASSIGNMENT',
      policyVersion: CONTROLLER_POLICY_VERSION,
      sessionId,
      diverted: true,
    };
  }

  // 4. Fault Tolerance: Detection failure or malformed score falls back to normal origin
  if (
    classification === 'UNAVAILABLE' ||
    typeof riskScore !== 'number' ||
    isNaN(riskScore) ||
    riskScore < 0 ||
    riskScore > 1
  ) {
    return {
      target: 'ORIGIN',
      reason: 'DETECTION_UNAVAILABLE_FALLBACK',
      policyVersion: CONTROLLER_POLICY_VERSION,
      sessionId,
      diverted: false,
    };
  }

  // 5. Benign Traffic: Route directly to legitimate origin
  if (classification === 'BENIGN' || riskScore < 0.40) {
    return {
      target: 'ORIGIN',
      reason: 'BENIGN_EVALUATION',
      policyVersion: CONTROLLER_POLICY_VERSION,
      sessionId,
      diverted: false,
    };
  }

  // 6. Suspicious / Low-Confidence Traffic: Keep on normal route in observation mode
  if (classification === 'SUSPICIOUS' || riskScore < deceptionScoreThreshold) {
    return {
      target: 'OBSERVE_ONLY',
      reason: 'SUSPICIOUS_OBSERVE_ONLY',
      policyVersion: CONTROLLER_POLICY_VERSION,
      sessionId,
      diverted: false,
    };
  }

  // 7. High-Confidence Malicious Traffic: Check for multi-factor corroboration
  // Must be classified as MALICIOUS, exceed threshold, and have either multi-factor evidence or score >= 0.75
  const hasCorroboratingEvidence = evidence.length >= 2 || riskScore >= 0.75;
  if (classification === 'MALICIOUS' && riskScore >= deceptionScoreThreshold && hasCorroboratingEvidence) {
    return {
      target: 'DECEPTION',
      reason: 'HIGH_CONFIDENCE_MALICIOUS_DIVERT',
      policyVersion: CONTROLLER_POLICY_VERSION,
      sessionId,
      diverted: true,
    };
  }

  // Fallback for single weak signals that do not meet strict multi-factor criteria
  return {
    target: 'OBSERVE_ONLY',
    reason: 'INSUFFICIENT_CORROBORATION_OBSERVE_ONLY',
    policyVersion: CONTROLLER_POLICY_VERSION,
    sessionId,
    diverted: false,
  };
}
