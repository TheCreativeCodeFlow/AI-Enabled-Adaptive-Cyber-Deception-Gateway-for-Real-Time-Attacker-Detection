/**
 * Deception Effectiveness Score (DES) Calculator
 *
 * Formal mathematical formulation:
 * DES = I[leak = 0] * (w_d * D_depth + w_c * C_consistency + w_t * T_dwell + w_e * E_engagement)
 *
 * Where:
 * - I[leak = 0]: Binary indicator gate. Zero if any attacker request leaks to the real origin.
 * - D_depth: Ratio of unique Deception State Graph (DSG) nodes explored.
 * - C_consistency: Fraction of synthetic responses returned without error or discontinuity.
 * - T_dwell: Attacker interaction depth normalized to target dwell threshold (K_dwell = 10).
 * - E_engagement: Fraction of diverse deceptive API endpoints engaged.
 */

export interface DESInputs {
  originLeakCount: number;
  uniqueDsgNodesVisited: number;
  totalAccessibleDsgNodes?: number;
  successfulDeceptionInteractions: number;
  totalDeceptionInteractions: number;
  uniqueDecoyEndpointsTargeted: number;
  totalDecoyEndpoints?: number;
  dwellTargetInteractions?: number;
}

export interface DESWeights {
  depth: number;
  consistency: number;
  dwell: number;
  engagement: number;
}

export interface DESResult {
  score: number; // Value in [0.0, 1.0]
  originLeakage: boolean;
  components: {
    depthScore: number;
    consistencyScore: number;
    dwellScore: number;
    engagementScore: number;
  };
  weights: DESWeights;
  rawInputs: {
    originLeakCount: number;
    uniqueDsgNodesVisited: number;
    successfulDeceptionInteractions: number;
    totalDeceptionInteractions: number;
    uniqueDecoyEndpointsTargeted: number;
  };
  limitations: string[];
}

export const DEFAULT_DES_WEIGHTS: DESWeights = {
  depth: 0.30,
  consistency: 0.30,
  dwell: 0.25,
  engagement: 0.15,
};

export const DES_METHODOLOGICAL_LIMITATIONS = [
  'Evaluated on synthetic benchmark workloads; synthetic performance metrics do not imply real-world deception efficacy against novel zero-days or skilled human adversaries.',
  'Dwell interaction normalization is calibrated for local benchmark scenarios (K=10 interactions) rather than long-term persistent human campaigns.',
  'DES measures synthetic fidelity, state continuity, and containment; it does not substitute for origin-level least-privilege or host-based security defenses.',
];

export function calculateDES(
  inputs: DESInputs,
  customWeights?: Partial<DESWeights>
): DESResult {
  const weights: DESWeights = {
    ...DEFAULT_DES_WEIGHTS,
    ...customWeights,
  };

  const totalDsgNodes = inputs.totalAccessibleDsgNodes && inputs.totalAccessibleDsgNodes > 0
    ? inputs.totalAccessibleDsgNodes
    : 4;
  const totalDecoyApis = inputs.totalDecoyEndpoints && inputs.totalDecoyEndpoints > 0
    ? inputs.totalDecoyEndpoints
    : 4;
  const dwellTarget = inputs.dwellTargetInteractions && inputs.dwellTargetInteractions > 0
    ? inputs.dwellTargetInteractions
    : 10;

  // Binary gate: If any request from an active session reached the real origin, DES is 0.0
  const hasOriginLeak = inputs.originLeakCount > 0;
  if (hasOriginLeak) {
    return {
      score: 0.0,
      originLeakage: true,
      components: {
        depthScore: 0.0,
        consistencyScore: 0.0,
        dwellScore: 0.0,
        engagementScore: 0.0,
      },
      weights,
      rawInputs: {
        originLeakCount: inputs.originLeakCount,
        uniqueDsgNodesVisited: inputs.uniqueDsgNodesVisited,
        successfulDeceptionInteractions: inputs.successfulDeceptionInteractions,
        totalDeceptionInteractions: inputs.totalDeceptionInteractions,
        uniqueDecoyEndpointsTargeted: inputs.uniqueDecoyEndpointsTargeted,
      },
      limitations: DES_METHODOLOGICAL_LIMITATIONS,
    };
  }

  // 1. Interaction Depth D_depth in [0, 1]
  const depthScore = Math.min(1.0, Math.max(0.0, inputs.uniqueDsgNodesVisited / totalDsgNodes));

  // 2. State Consistency C_consistency in [0, 1]
  const consistencyScore = inputs.totalDeceptionInteractions > 0
    ? Math.min(1.0, Math.max(0.0, inputs.successfulDeceptionInteractions / inputs.totalDeceptionInteractions))
    : 0.0;

  // 3. Attacker Dwell T_dwell in [0, 1]
  const dwellScore = Math.min(1.0, Math.max(0.0, inputs.totalDeceptionInteractions / dwellTarget));

  // 4. Decoy Endpoint Diversity E_engagement in [0, 1]
  const engagementScore = Math.min(1.0, Math.max(0.0, inputs.uniqueDecoyEndpointsTargeted / totalDecoyApis));

  // Weighted sum
  const rawScore =
    weights.depth * depthScore +
    weights.consistency * consistencyScore +
    weights.dwell * dwellScore +
    weights.engagement * engagementScore;

  const score = parseFloat(Math.min(1.0, Math.max(0.0, rawScore)).toFixed(4));

  return {
    score,
    originLeakage: false,
    components: {
      depthScore: parseFloat(depthScore.toFixed(4)),
      consistencyScore: parseFloat(consistencyScore.toFixed(4)),
      dwellScore: parseFloat(dwellScore.toFixed(4)),
      engagementScore: parseFloat(engagementScore.toFixed(4)),
    },
    weights,
    rawInputs: {
      originLeakCount: inputs.originLeakCount,
      uniqueDsgNodesVisited: inputs.uniqueDsgNodesVisited,
      successfulDeceptionInteractions: inputs.successfulDeceptionInteractions,
      totalDeceptionInteractions: inputs.totalDeceptionInteractions,
      uniqueDecoyEndpointsTargeted: inputs.uniqueDecoyEndpointsTargeted,
    },
    limitations: DES_METHODOLOGICAL_LIMITATIONS,
  };
}
