export type DsgNodeId = 'entrypoint' | 'catalog' | 'users' | 'files' | 'admin' | 'auth';

export type ServiceType =
  | 'public'
  | 'catalog'
  | 'user_management'
  | 'document_store'
  | 'admin_control'
  | 'authentication';

export interface DsgNode {
  id: DsgNodeId;
  name: string;
  serviceType: ServiceType;
  stateVersion: number;
  permittedTransitions: DsgNodeId[];
  requiredRole?: 'user' | 'admin' | 'auditor';
}

export interface SyntheticUser {
  id: string;
  username: string;
  email: string;
  displayName: string;
  role: 'user' | 'admin' | 'auditor';
  department: string;
  isDecoy: boolean;
  createdAt: string;
}

export interface SyntheticFile {
  id: string;
  filename: string;
  path: string;
  sizeBytes: number;
  mimeType: string;
  classification: 'PUBLIC' | 'INTERNAL' | 'CONFIDENTIAL' | 'RESTRICTED';
  checksumSha256: string;
  isDecoy: boolean;
  lastModified: string;
}

export interface SyntheticService {
  id: string;
  name: string;
  description: string;
  endpoint: string;
  status: 'online' | 'degraded' | 'maintenance';
  version: string;
  isDecoy: boolean;
}

export type DeceptionStrategyAction =
  | 'EXPOSE_SYNTHETIC_SERVICE'
  | 'ADD_SYNTHETIC_DECOY_RECORD'
  | 'INCREASE_OBSERVATION_DETAIL'
  | 'MAINTAIN_CURRENT_STATE'
  | 'DISABLE_DECEPTION';

export type ObservationLevel = 'standard' | 'high_detail';

export interface SessionInteraction {
  timestamp: string;
  method: string;
  path: string;
  targetNode: DsgNodeId;
  statusCode: number;
  strategyExecuted: DeceptionStrategyAction;
  details?: Record<string, unknown>;
}

export interface DeceptionSession {
  sessionId: string;
  createdAt: string;
  lastActiveAt: string;
  expiresAt: number; // Unix ms
  authenticatedUser: {
    id: string;
    username: string;
    email: string;
    role: 'user' | 'admin' | 'auditor';
    token: string;
  } | null;
  observationLevel: ObservationLevel;
  deceptionEnabled: boolean;
  currentNode: DsgNodeId;
  visitedNodes: DsgNodeId[];
  interactions: SessionInteraction[];
  dynamicUsers: SyntheticUser[];
  dynamicFiles: SyntheticFile[];
  dynamicServices: SyntheticService[];
}

export interface DeceptionErrorResponse {
  error: string;
  message: string;
  code: string;
  requestId?: string;
  timestamp: string;
}
