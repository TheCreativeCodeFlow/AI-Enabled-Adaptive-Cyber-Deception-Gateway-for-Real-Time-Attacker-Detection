import { PROTECTED_POLICY, validateNodeId } from './policy';
import { DeceptionSession, DsgNode, DsgNodeId } from './types';

/**
 * Standard node registry for the initial Deception State Graph.
 * Each node represents a distinct synthetic service area with strict transition boundaries.
 */
export const INITIAL_DSG_NODES: Readonly<Record<DsgNodeId, Readonly<DsgNode>>> = Object.freeze({
  entrypoint: Object.freeze<DsgNode>({
    id: 'entrypoint',
    name: 'Application Gateway Entrypoint',
    serviceType: 'public',
    stateVersion: 1,
    permittedTransitions: ['catalog', 'users', 'files', 'admin', 'auth'],
  }),
  catalog: Object.freeze<DsgNode>({
    id: 'catalog',
    name: 'Synthetic Service Catalog',
    serviceType: 'catalog',
    stateVersion: 1,
    permittedTransitions: ['entrypoint', 'users', 'files', 'admin', 'auth'],
  }),
  users: Object.freeze<DsgNode>({
    id: 'users',
    name: 'Synthetic User Directory',
    serviceType: 'user_management',
    stateVersion: 1,
    permittedTransitions: ['entrypoint', 'catalog', 'files', 'admin', 'auth'],
  }),
  files: Object.freeze<DsgNode>({
    id: 'files',
    name: 'Synthetic Document Store',
    serviceType: 'document_store',
    stateVersion: 1,
    permittedTransitions: ['entrypoint', 'catalog', 'users', 'admin', 'auth'],
  }),
  admin: Object.freeze<DsgNode>({
    id: 'admin',
    name: 'Simulated Administration Console',
    serviceType: 'admin_control',
    stateVersion: 1,
    permittedTransitions: ['entrypoint', 'catalog', 'users', 'files', 'auth'],
    requiredRole: 'admin',
  }),
  auth: Object.freeze<DsgNode>({
    id: 'auth',
    name: 'Synthetic Authentication Service',
    serviceType: 'authentication',
    stateVersion: 1,
    permittedTransitions: ['entrypoint', 'catalog', 'users', 'files', 'admin'],
  }),
});

/**
 * Maps incoming HTTP route paths to the appropriate DSG Node ID.
 */
export function resolveNodeFromPath(path: string): DsgNodeId {
  const normalized = path.toLowerCase().replace(/\/+$/, '') || '/';

  if (normalized === '/' || normalized === '/health') {
    return 'entrypoint';
  }
  if (normalized.startsWith('/api/catalog')) {
    return 'catalog';
  }
  if (normalized.startsWith('/api/users')) {
    return 'users';
  }
  if (normalized.startsWith('/api/files')) {
    return 'files';
  }
  if (normalized.startsWith('/api/admin')) {
    return 'admin';
  }
  if (normalized.startsWith('/api/auth')) {
    return 'auth';
  }

  return 'entrypoint';
}

/**
 * Returns a node by its identifier.
 */
export function getDsgNode(nodeId: string): DsgNode | null {
  if (!validateNodeId(nodeId)) {
    return null;
  }
  return INITIAL_DSG_NODES[nodeId] || null;
}

/**
 * Validates whether a transition from currentNode to targetNode is allowed by DSG rules.
 */
export function validateTransition(
  fromNodeId: DsgNodeId,
  toNodeId: DsgNodeId
): { valid: boolean; reason?: string } {
  if (!validateNodeId(toNodeId)) {
    return { valid: false, reason: `Target node "${toNodeId}" is not permitted by Protected Policy.` };
  }

  const fromNode = INITIAL_DSG_NODES[fromNodeId];
  if (!fromNode) {
    return { valid: false, reason: `Origin node "${fromNodeId}" does not exist in graph.` };
  }

  if (fromNodeId === toNodeId) {
    return { valid: true }; // Same node interaction is valid
  }

  if (!fromNode.permittedTransitions.includes(toNodeId)) {
    return {
      valid: false,
      reason: `Forbidden DSG transition: cannot navigate from "${fromNodeId}" to "${toNodeId}".`,
    };
  }

  return { valid: true };
}

/**
 * Executes a validated graph transition for the given session.
 */
export function executeTransition(
  session: DeceptionSession,
  targetNodeId: DsgNodeId
): { success: boolean; error?: string } {
  const check = validateTransition(session.currentNode, targetNodeId);
  if (!check.valid) {
    return { success: false, error: check.reason };
  }

  // Update session node in observation layer
  session.currentNode = targetNodeId;
  if (!session.visitedNodes.includes(targetNodeId)) {
    session.visitedNodes.push(targetNodeId);
  }

  return { success: true };
}
