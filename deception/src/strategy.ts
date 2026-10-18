import { PROTECTED_POLICY, validateStrategyAction } from './policy';
import { DECOY_FILE_TEMPLATE, DECOY_SERVICE_TEMPLATE } from './syntheticData';
import { DeceptionSession, DeceptionStrategyAction } from './types';

export interface StrategyContext {
  method: string;
  path: string;
  statusCode: number;
}

/**
 * Deterministic Deception Strategy Selector.
 * Selects an action strictly from the Protected Policy allowlist based on session history.
 */
export function selectDeceptionStrategy(
  session: DeceptionSession,
  context: StrategyContext
): DeceptionStrategyAction {
  if (!session.deceptionEnabled) {
    return 'MAINTAIN_CURRENT_STATE';
  }

  let proposedAction: DeceptionStrategyAction = 'MAINTAIN_CURRENT_STATE';

  const visitedSensitiveCount = session.visitedNodes.filter((n) =>
    ['admin', 'files', 'users'].includes(n)
  ).length;

  // Rule 1: Document / File probing -> Inject decoy credentials file into dynamic file layer
  if (
    context.path.startsWith('/api/files') &&
    !session.dynamicFiles.some((f) => f.isDecoy)
  ) {
    proposedAction = 'ADD_SYNTHETIC_DECOY_RECORD';
  }
  // Rule 2: Catalog inspection -> Expose legacy decoy service in dynamic catalog
  else if (
    context.path.startsWith('/api/catalog') &&
    !session.dynamicServices.some((s) => s.isDecoy)
  ) {
    proposedAction = 'EXPOSE_SYNTHETIC_SERVICE';
  }
  // Rule 3: Attacker reconnaissance escalation -> Increase observation fidelity
  else if (
    (session.interactions.length >= 6 || visitedSensitiveCount >= 2) &&
    session.observationLevel === 'standard'
  ) {
    proposedAction = 'INCREASE_OBSERVATION_DETAIL';
  }

  // Safety Assertion: Validate that proposed action is strictly permitted by the protected policy
  if (!validateStrategyAction(proposedAction)) {
    console.warn(`[Strategy Selector] Rejected unauthorized action proposal: "${proposedAction}"`);
    return 'MAINTAIN_CURRENT_STATE';
  }

  return proposedAction;
}

/**
 * Applies a validated strategy action to the session's controlled dynamic layer.
 * Strictly bounded: no command execution, no network calls, no disk writes.
 */
export function applyDeceptionStrategy(
  session: DeceptionSession,
  action: DeceptionStrategyAction
): { applied: boolean; action: DeceptionStrategyAction; note?: string } {
  // Validate against Protected Policy
  if (!validateStrategyAction(action)) {
    return {
      applied: false,
      action: 'MAINTAIN_CURRENT_STATE',
      note: `Action "${action}" is not permitted by Protected Policy.`,
    };
  }

  switch (action) {
    case 'INCREASE_OBSERVATION_DETAIL':
      session.observationLevel = 'high_detail';
      return { applied: true, action, note: 'Observation level set to high_detail' };

    case 'ADD_SYNTHETIC_DECOY_RECORD': {
      if (session.dynamicFiles.length >= PROTECTED_POLICY.maxDecoyRecordsPerSession) {
        return { applied: false, action, note: 'Max decoy records limit reached' };
      }
      const alreadyExists = session.dynamicFiles.some((f) => f.id === DECOY_FILE_TEMPLATE.id);
      if (!alreadyExists) {
        session.dynamicFiles.push({ ...DECOY_FILE_TEMPLATE, lastModified: new Date().toISOString() });
      }
      return { applied: true, action, note: 'Injected decoy vault file into synthetic files' };
    }

    case 'EXPOSE_SYNTHETIC_SERVICE': {
      const alreadyExists = session.dynamicServices.some((s) => s.id === DECOY_SERVICE_TEMPLATE.id);
      if (!alreadyExists) {
        session.dynamicServices.push({ ...DECOY_SERVICE_TEMPLATE });
      }
      return { applied: true, action, note: 'Exposed decoy administration API in catalog' };
    }

    case 'DISABLE_DECEPTION':
      session.deceptionEnabled = false;
      return { applied: true, action, note: 'Deception disabled for session' };

    case 'MAINTAIN_CURRENT_STATE':
    default:
      return { applied: true, action: 'MAINTAIN_CURRENT_STATE' };
  }
}
