import { DeceptionStrategyAction, DsgNodeId } from './types';

export interface ProtectedPolicyLayer {
  readonly version: string;
  readonly allowedNodes: readonly DsgNodeId[];
  readonly allowedStrategyActions: readonly DeceptionStrategyAction[];
  readonly maxInteractionsPerSession: number;
  readonly maxDecoyRecordsPerSession: number;
  readonly safetyConstraints: {
    readonly preventCommandExecution: true;
    readonly preventArbitraryNetworkEgress: true;
    readonly preventHostFileSystemAccess: true;
    readonly preventRealDatabaseAccess: true;
    readonly preventPolicyMutation: true;
  };
}

function deepFreeze<T extends object>(obj: T): Readonly<T> {
  Object.keys(obj).forEach((prop) => {
    const val = (obj as Record<string, unknown>)[prop];
    if (val && typeof val === 'object' && !Object.isFrozen(val)) {
      deepFreeze(val as object);
    }
  });
  return Object.freeze(obj);
}

/**
 * The Protected Policy Layer defines immutable safety constraints,
 * allowed graph transitions, and authorized strategy actions.
 * Runtime code cannot alter or override this configuration.
 */
export const PROTECTED_POLICY: Readonly<ProtectedPolicyLayer> = deepFreeze({
  version: '1.0.0-immutable',
  allowedNodes: ['entrypoint', 'catalog', 'users', 'files', 'admin', 'auth'] as const,
  allowedStrategyActions: [
    'EXPOSE_SYNTHETIC_SERVICE',
    'ADD_SYNTHETIC_DECOY_RECORD',
    'INCREASE_OBSERVATION_DETAIL',
    'MAINTAIN_CURRENT_STATE',
    'DISABLE_DECEPTION',
  ] as const,
  maxInteractionsPerSession: 500,
  maxDecoyRecordsPerSession: 50,
  safetyConstraints: {
    preventCommandExecution: true,
    preventArbitraryNetworkEgress: true,
    preventHostFileSystemAccess: true,
    preventRealDatabaseAccess: true,
    preventPolicyMutation: true,
  },
});

/**
 * Validates that a requested strategy action is explicitly permitted by the protected policy.
 */
export function validateStrategyAction(action: string): action is DeceptionStrategyAction {
  return (PROTECTED_POLICY.allowedStrategyActions as readonly string[]).includes(action);
}

/**
 * Validates that a requested node identifier is authorized within the protected policy.
 */
export function validateNodeId(nodeId: string): nodeId is DsgNodeId {
  return (PROTECTED_POLICY.allowedNodes as readonly string[]).includes(nodeId);
}
