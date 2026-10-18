import { SyntheticFile, SyntheticService, SyntheticUser } from './types';

export interface SyntheticAuthAccount {
  username: string;
  email: string;
  passwordHash: string; // Plaintext or simulated hash for synthetic comparison
  role: 'user' | 'admin' | 'auditor';
  userRecordId: string;
}

export const SYNTHETIC_ACCOUNTS: readonly SyntheticAuthAccount[] = [
  {
    username: 'admin',
    email: 'admin@synthetic.local',
    passwordHash: 'P@ssw0rd2026!',
    role: 'admin',
    userRecordId: 'usr-syn-001',
  },
  {
    username: 'developer',
    email: 'developer@synthetic.local',
    passwordHash: 'DevSecret2026!',
    role: 'user',
    userRecordId: 'usr-syn-002',
  },
  {
    username: 'auditor',
    email: 'auditor@synthetic.local',
    passwordHash: 'AuditRead2026!',
    role: 'auditor',
    userRecordId: 'usr-syn-003',
  },
];

export const INITIAL_SYNTHETIC_USERS: readonly SyntheticUser[] = [
  {
    id: 'usr-syn-001',
    username: 'admin',
    email: 'admin@synthetic.local',
    displayName: 'System Administrator',
    role: 'admin',
    department: 'IT Security Operations',
    isDecoy: false,
    createdAt: '2026-01-10T08:00:00.000Z',
  },
  {
    id: 'usr-syn-002',
    username: 'alice.jenkins',
    email: 'alice.jenkins@synthetic.local',
    displayName: 'Alice Jenkins',
    role: 'user',
    department: 'Core Infrastructure',
    isDecoy: false,
    createdAt: '2026-02-15T09:30:00.000Z',
  },
  {
    id: 'usr-syn-003',
    username: 'eve.white',
    email: 'eve.white@synthetic.local',
    displayName: 'Eve White',
    role: 'auditor',
    department: 'Regulatory Compliance',
    isDecoy: false,
    createdAt: '2026-03-01T11:15:00.000Z',
  },
  {
    id: 'usr-syn-004',
    username: 'bob.smith',
    email: 'bob.smith@synthetic.local',
    displayName: 'Bob Smith',
    role: 'user',
    department: 'Financial Analytics',
    isDecoy: false,
    createdAt: '2026-03-12T14:45:00.000Z',
  },
];

export const INITIAL_SYNTHETIC_FILES: readonly SyntheticFile[] = [
  {
    id: 'file-syn-001',
    filename: 'corporate_security_policy_2026.pdf',
    path: '/documents/public/corporate_security_policy_2026.pdf',
    sizeBytes: 154200,
    mimeType: 'application/pdf',
    classification: 'PUBLIC',
    checksumSha256: '9f83c689e2f9742517b61344161f3a206013a926159b3529a60077e201613b3a',
    isDecoy: false,
    lastModified: '2026-01-05T10:00:00.000Z',
  },
  {
    id: 'file-syn-002',
    filename: 'quarterly_financial_summary_q3.xlsx',
    path: '/documents/internal/quarterly_financial_summary_q3.xlsx',
    sizeBytes: 894500,
    mimeType: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    classification: 'CONFIDENTIAL',
    checksumSha256: 'a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0',
    isDecoy: false,
    lastModified: '2026-09-30T16:20:00.000Z',
  },
  {
    id: 'file-syn-003',
    filename: 'datacenter_vpn_profile.ovpn',
    path: '/network/config/datacenter_vpn_profile.ovpn',
    sizeBytes: 4210,
    mimeType: 'application/x-openvpn-profile',
    classification: 'RESTRICTED',
    checksumSha256: 'd4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35',
    isDecoy: false,
    lastModified: '2026-04-12T12:05:00.000Z',
  },
  {
    id: 'file-syn-004',
    filename: 'schema_migrations_v4.sql',
    path: '/db/migrations/schema_migrations_v4.sql',
    sizeBytes: 45620,
    mimeType: 'application/sql',
    classification: 'INTERNAL',
    checksumSha256: '4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a',
    isDecoy: false,
    lastModified: '2026-08-19T08:30:00.000Z',
  },
];

export const INITIAL_SYNTHETIC_SERVICES: readonly SyntheticService[] = [
  {
    id: 'srv-syn-001',
    name: 'Identity & Authentication Gateway',
    description: 'Handles synthetic user credential validation and session token issuance.',
    endpoint: '/api/auth',
    status: 'online',
    version: '2.4.1',
    isDecoy: false,
  },
  {
    id: 'srv-syn-002',
    name: 'Directory Service API',
    description: 'Provides synthetic user directory records and organizational metadata.',
    endpoint: '/api/users',
    status: 'online',
    version: '1.9.0',
    isDecoy: false,
  },
  {
    id: 'srv-syn-003',
    name: 'Document Management Store',
    description: 'Simulated repository for internal enterprise files and reports.',
    endpoint: '/api/files',
    status: 'online',
    version: '3.1.0',
    isDecoy: false,
  },
  {
    id: 'srv-syn-004',
    name: 'System Administration Console',
    description: 'Administrative control plane for platform telemetry and configuration.',
    endpoint: '/api/admin',
    status: 'online',
    version: '4.0.0-rc1',
    isDecoy: false,
  },
];

// Decoy templates for dynamic injection by strategy
export const DECOY_FILE_TEMPLATE: SyntheticFile = {
  id: 'file-decoy-999',
  filename: 'master_passwords_vault.kdbx',
  path: '/secure/vault/master_passwords_vault.kdbx',
  sizeBytes: 671088,
  mimeType: 'application/x-keepass2',
  classification: 'RESTRICTED',
  checksumSha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
  isDecoy: true,
  lastModified: new Date().toISOString(),
};

export const DECOY_SERVICE_TEMPLATE: SyntheticService = {
  id: 'srv-decoy-999',
  name: 'Internal Decoy Administration API',
  description: 'Simulated legacy management endpoint with elevated honeypot instrumentation.',
  endpoint: '/api/internal/management',
  status: 'online',
  version: '0.9.1-beta',
  isDecoy: true,
};
