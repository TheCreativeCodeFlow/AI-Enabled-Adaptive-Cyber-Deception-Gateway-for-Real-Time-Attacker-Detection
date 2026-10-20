import { Pool, QueryResult } from 'pg';
import crypto from 'node:crypto';
import { getConfig } from './config';

export interface OperatorRecord {
  id: string;
  username: string;
  email: string;
  password_hash: string;
  role: 'admin' | 'analyst';
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export interface AuditLogRecord {
  id: string;
  operator_id?: string;
  operator_username?: string;
  action: string;
  status: 'SUCCESS' | 'FAILED' | 'FORBIDDEN';
  ip_address: string;
  details: Record<string, any>;
  created_at: string;
}

export interface OperatorSessionRecord {
  id: string;
  operator_id: string;
  token_hash: string;
  expires_at: string;
  created_at: string;
  revoked: boolean;
}

export interface OrganisationRecord {
  id: string;
  name: string;
  slug: string;
  description: string;
  created_by?: string;
  created_at: string;
  updated_at: string;
}

export type OrgRole = 'org_owner' | 'security_admin' | 'security_analyst';

export interface OrgMembershipRecord {
  id: string;
  organisation_id: string;
  operator_id: string;
  role: OrgRole;
  created_at: string;
  updated_at: string;
  // Joins
  username?: string;
  email?: string;
}

export type AppEnvironment = 'production' | 'staging' | 'development';
export type VerificationStatus = 'unverified' | 'pending' | 'verified' | 'rejected';
export type ActivationStatus = 'inactive' | 'pending_approval' | 'active' | 'disabled';

export interface ApplicationRecord {
  id: string;
  organisation_id: string;
  display_name: string;
  environment: AppEnvironment;
  approved_domain: string;
  configured_origin: string;
  verification_status: VerificationStatus;
  activation_status: ActivationStatus;
  created_by?: string;
  created_at: string;
  updated_at: string;
}

export interface DomainVerificationRecord {
  id: string;
  application_id: string;
  organisation_id: string;
  domain: string;
  token: string;
  record_name: string;
  record_type: 'TXT';
  status: 'pending' | 'verified' | 'expired' | 'failed';
  expires_at: string;
  verified_at?: string;
  attempts_count: number;
  last_error?: string;
  created_at: string;
  updated_at: string;
}

export interface ApplicationProtectionRecord {
  id: string;
  application_id: string;
  organisation_id: string;
  routing_mode: 'shadow' | 'active';
  deception_threshold: number;
  emergency_disable: boolean;
  quarantine_on_failure: boolean;
  updated_at: string;
}

export interface OrgAuditEventRecord {
  id: string;
  organisation_id: string;
  actor_id?: string;
  actor_username?: string;
  action: string;
  resource_type: string;
  resource_id?: string;
  status: 'SUCCESS' | 'FAILED' | 'FORBIDDEN';
  ip_address: string;
  details: Record<string, any>;
  created_at: string;
}

export interface SecurityEventRecord {
  id: string;
  request_id: string;
  session_id: string;
  organisation_id?: string;
  application_id?: string;
  timestamp: string;
  method: string;
  path: string;
  status_code: number;
  duration_ms: number;
  detection_score?: number;
  detection_classification?: string;
  detection_latency_ms?: number;
  routing_decision: 'ORIGIN' | 'DECEPTION' | 'OBSERVE_ONLY';
  routing_reason: string;
  routing_mode: 'shadow' | 'active';
  deception_node?: string;
  deception_strategy?: string;
  failure_quarantined: boolean;
  client_ip: string;
  metadata?: Record<string, any>;
  created_at: string;
}

let pool: Pool | null = null;
let useInMemory = false;

// In-memory fallback stores for local testing without PostgreSQL
export const memOperators = new Map<string, OperatorRecord>();
export const memAuditLogs: AuditLogRecord[] = [];
export const memSessions = new Map<string, OperatorSessionRecord>();
export const memOrganisations = new Map<string, OrganisationRecord>();
export const memMemberships = new Map<string, OrgMembershipRecord>();
export const memApplications = new Map<string, ApplicationRecord>();
export const memVerifications = new Map<string, DomainVerificationRecord>();
export const memProtections = new Map<string, ApplicationProtectionRecord>();
export const memOrgAuditEvents: OrgAuditEventRecord[] = [];
export const memSecurityEvents: SecurityEventRecord[] = [];

export function getPool(): Pool | null {
  return pool;
}

export function setUseInMemory(flag: boolean) {
  useInMemory = flag;
}

export async function initDb(): Promise<void> {
  const config = getConfig();

  if (useInMemory) {
    return;
  }

  try {
    pool = new Pool({
      connectionString: config.databaseUrl,
      connectionTimeoutMillis: 3000,
      idleTimeoutMillis: 10000,
      max: 10,
    });

    // Test connection with a fast query
    const client = await pool.connect();
    try {
      await client.query(`
        CREATE TABLE IF NOT EXISTS operators (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          username VARCHAR(64) UNIQUE NOT NULL,
          email VARCHAR(255) UNIQUE NOT NULL,
          password_hash VARCHAR(255) NOT NULL,
          role VARCHAR(32) NOT NULL DEFAULT 'analyst' CHECK (role IN ('admin', 'analyst')),
          is_active BOOLEAN NOT NULL DEFAULT true,
          created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
          updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS operator_sessions (
          id VARCHAR(64) PRIMARY KEY,
          operator_id UUID NOT NULL REFERENCES operators(id) ON DELETE CASCADE,
          token_hash VARCHAR(64) NOT NULL,
          expires_at TIMESTAMPTZ NOT NULL,
          created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
          revoked BOOLEAN DEFAULT false
        );

        CREATE TABLE IF NOT EXISTS audit_logs (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          operator_id UUID REFERENCES operators(id) ON DELETE SET NULL,
          operator_username VARCHAR(64),
          action VARCHAR(64) NOT NULL,
          status VARCHAR(32) NOT NULL,
          ip_address VARCHAR(45) NOT NULL,
          details JSONB DEFAULT '{}',
          created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS organisations (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          name VARCHAR(128) NOT NULL,
          slug VARCHAR(128) UNIQUE NOT NULL,
          description TEXT DEFAULT '',
          created_by UUID REFERENCES operators(id) ON DELETE SET NULL,
          created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
          updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS organisation_memberships (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          organisation_id UUID NOT NULL REFERENCES organisations(id) ON DELETE CASCADE,
          operator_id UUID NOT NULL REFERENCES operators(id) ON DELETE CASCADE,
          role VARCHAR(32) NOT NULL CHECK (role IN ('org_owner', 'security_admin', 'security_analyst')),
          created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
          updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
          UNIQUE(organisation_id, operator_id)
        );

        CREATE TABLE IF NOT EXISTS applications (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          organisation_id UUID NOT NULL REFERENCES organisations(id) ON DELETE CASCADE,
          display_name VARCHAR(128) NOT NULL,
          environment VARCHAR(32) NOT NULL DEFAULT 'production' CHECK (environment IN ('production', 'staging', 'development')),
          approved_domain VARCHAR(255) NOT NULL,
          configured_origin VARCHAR(255) NOT NULL,
          verification_status VARCHAR(32) NOT NULL DEFAULT 'unverified' CHECK (verification_status IN ('unverified', 'pending', 'verified', 'rejected')),
          activation_status VARCHAR(32) NOT NULL DEFAULT 'inactive' CHECK (activation_status IN ('inactive', 'pending_approval', 'active', 'disabled')),
          created_by UUID REFERENCES operators(id) ON DELETE SET NULL,
          created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
          updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
          UNIQUE(organisation_id, approved_domain)
        );

        CREATE TABLE IF NOT EXISTS domain_verifications (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          application_id UUID NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
          organisation_id UUID NOT NULL REFERENCES organisations(id) ON DELETE CASCADE,
          domain VARCHAR(255) NOT NULL,
          token VARCHAR(128) NOT NULL,
          record_name VARCHAR(255) NOT NULL,
          record_type VARCHAR(16) NOT NULL DEFAULT 'TXT',
          status VARCHAR(32) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'verified', 'expired', 'failed')),
          expires_at TIMESTAMPTZ NOT NULL,
          verified_at TIMESTAMPTZ,
          attempts_count INT NOT NULL DEFAULT 0,
          last_error TEXT,
          created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
          updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS application_protections (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          application_id UUID UNIQUE NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
          organisation_id UUID NOT NULL REFERENCES organisations(id) ON DELETE CASCADE,
          routing_mode VARCHAR(32) NOT NULL DEFAULT 'shadow' CHECK (routing_mode IN ('shadow', 'active')),
          deception_threshold NUMERIC(3, 2) NOT NULL DEFAULT 0.70,
          emergency_disable BOOLEAN NOT NULL DEFAULT false,
          quarantine_on_failure BOOLEAN NOT NULL DEFAULT true,
          updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS organisation_audit_events (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          organisation_id UUID NOT NULL REFERENCES organisations(id) ON DELETE CASCADE,
          actor_id UUID REFERENCES operators(id) ON DELETE SET NULL,
          actor_username VARCHAR(64),
          action VARCHAR(64) NOT NULL,
          resource_type VARCHAR(64) NOT NULL,
          resource_id VARCHAR(64),
          status VARCHAR(32) NOT NULL,
          ip_address VARCHAR(45) NOT NULL,
          details JSONB DEFAULT '{}',
          created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS security_events (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          request_id VARCHAR(128) NOT NULL,
          session_id VARCHAR(128) NOT NULL,
          organisation_id UUID REFERENCES organisations(id) ON DELETE CASCADE,
          application_id UUID REFERENCES applications(id) ON DELETE CASCADE,
          timestamp TIMESTAMPTZ NOT NULL,
          method VARCHAR(16) NOT NULL,
          path VARCHAR(1024) NOT NULL,
          status_code INT NOT NULL,
          duration_ms FLOAT NOT NULL,
          detection_score FLOAT,
          detection_classification VARCHAR(64),
          detection_latency_ms FLOAT,
          routing_decision VARCHAR(32) NOT NULL,
          routing_reason VARCHAR(128) NOT NULL,
          routing_mode VARCHAR(32) NOT NULL DEFAULT 'shadow',
          deception_node VARCHAR(128),
          deception_strategy VARCHAR(128),
          failure_quarantined BOOLEAN NOT NULL DEFAULT false,
          client_ip VARCHAR(128) NOT NULL,
          metadata JSONB DEFAULT '{}',
          created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
        );

        CREATE INDEX IF NOT EXISTS idx_operators_username ON operators(username);
        CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_organisations_slug ON organisations(slug);
        CREATE INDEX IF NOT EXISTS idx_org_memberships_org ON organisation_memberships(organisation_id);
        CREATE INDEX IF NOT EXISTS idx_org_memberships_op ON organisation_memberships(operator_id);
        CREATE INDEX IF NOT EXISTS idx_applications_org ON applications(organisation_id);
        CREATE INDEX IF NOT EXISTS idx_domain_verifications_app ON domain_verifications(application_id);
        CREATE INDEX IF NOT EXISTS idx_org_audit_org_created ON organisation_audit_events(organisation_id, created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_security_events_org ON security_events(organisation_id, created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_security_events_app ON security_events(application_id, created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_security_events_req ON security_events(request_id);
        CREATE INDEX IF NOT EXISTS idx_security_events_sess ON security_events(session_id);
        CREATE INDEX IF NOT EXISTS idx_security_events_decision ON security_events(routing_decision);
      `);
      console.log('[Backend-DB] PostgreSQL migrations verified successfully.');
    } finally {
      client.release();
    }
  } catch (err: any) {
    console.warn(
      `[Backend-DB] PostgreSQL not reachable at ${config.databaseUrl} (${err.message}). Falling back to secure in-memory store for local testing.`
    );
    useInMemory = true;
    if (pool) {
      await pool.end().catch(() => {});
      pool = null;
    }
  }
}

// Parameterized query execution
export async function query(text: string, params?: any[]): Promise<QueryResult | any> {
  if (pool && !useInMemory) {
    return pool.query(text, params);
  }

  // In-memory mock query handler for unit testing
  return executeInMemoryQuery(text, params || []);
}

function executeInMemoryQuery(text: string, params: any[]): { rows: any[]; rowCount: number } {
  const norm = text.toLowerCase().replace(/\s+/g, ' ');

  if (norm.includes('insert into operators')) {
    const username = params[0];
    const email = params[1];
    const password_hash = params[2];
    const role = params[3] || 'analyst';

    // Check unique constraints
    for (const op of memOperators.values()) {
      if (op.username.toLowerCase() === username.toLowerCase()) {
        const error: any = new Error('duplicate key value violates unique constraint "operators_username_key"');
        error.code = '23505';
        throw error;
      }
      if (op.email.toLowerCase() === email.toLowerCase()) {
        const error: any = new Error('duplicate key value violates unique constraint "operators_email_key"');
        error.code = '23505';
        throw error;
      }
    }

    const newOp: OperatorRecord = {
      id: crypto.randomUUID(),
      username,
      email,
      password_hash,
      role,
      is_active: true,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };
    memOperators.set(newOp.id, newOp);
    return { rows: [newOp], rowCount: 1 };
  }

  if (norm.includes('select') && norm.includes('from operators') && norm.includes('where username = $1')) {
    const username = (params[0] || '').toLowerCase();
    const found = Array.from(memOperators.values()).find(
      (op) => op.username.toLowerCase() === username
    );
    return { rows: found ? [found] : [], rowCount: found ? 1 : 0 };
  }

  if (norm.includes('select') && norm.includes('from operators') && norm.includes('where id = $1')) {
    const id = params[0];
    const found = memOperators.get(id);
    return { rows: found ? [found] : [], rowCount: found ? 1 : 0 };
  }

  if (norm.includes('insert into audit_logs')) {
    const newLog: AuditLogRecord = {
      id: crypto.randomUUID(),
      operator_id: params[0],
      operator_username: params[1],
      action: params[2],
      status: params[3],
      ip_address: params[4],
      details: typeof params[5] === 'string' ? JSON.parse(params[5]) : params[5] || {},
      created_at: new Date().toISOString(),
    };
    memAuditLogs.push(newLog);
    return { rows: [newLog], rowCount: 1 };
  }

  if (norm.includes('select') && norm.includes('from audit_logs')) {
    const sorted = [...memAuditLogs].reverse();
    return { rows: sorted, rowCount: sorted.length };
  }

  if (norm.includes('insert into operator_sessions')) {
    const session: OperatorSessionRecord = {
      id: params[0],
      operator_id: params[1],
      token_hash: params[2],
      expires_at: params[3],
      created_at: new Date().toISOString(),
      revoked: false,
    };
    memSessions.set(session.id, session);
    return { rows: [session], rowCount: 1 };
  }

  if (norm.includes('update operator_sessions set revoked = true')) {
    const id = params[0];
    const session = memSessions.get(id);
    if (session) {
      session.revoked = true;
    }
    return { rows: session ? [session] : [], rowCount: session ? 1 : 0 };
  }

  // Stage 7: Organisations
  if (norm.includes('insert into organisations')) {
    const name = params[0];
    const slug = params[1];
    const description = params[2] || '';
    const created_by = params[3] || null;

    for (const org of memOrganisations.values()) {
      if (org.slug.toLowerCase() === slug.toLowerCase()) {
        const error: any = new Error('duplicate key value violates unique constraint "organisations_slug_key"');
        error.code = '23505';
        throw error;
      }
    }

    const newOrg: OrganisationRecord = {
      id: crypto.randomUUID(),
      name,
      slug,
      description,
      created_by,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };
    memOrganisations.set(newOrg.id, newOrg);
    return { rows: [newOrg], rowCount: 1 };
  }

  if (norm.includes('select') && norm.includes('from organisations') && norm.includes('where id = $1')) {
    const id = params[0];
    const org = memOrganisations.get(id);
    return { rows: org ? [org] : [], rowCount: org ? 1 : 0 };
  }

  if (norm.includes('select') && norm.includes('from organisations') && norm.includes('where slug = $1')) {
    const slug = (params[0] || '').toLowerCase();
    const found = Array.from(memOrganisations.values()).find((o) => o.slug.toLowerCase() === slug);
    return { rows: found ? [found] : [], rowCount: found ? 1 : 0 };
  }

  if (norm.includes('select') && norm.includes('from organisations o join organisation_memberships m')) {
    const operatorId = params[0];
    const memberships = Array.from(memMemberships.values()).filter((m) => m.operator_id === operatorId);
    const orgs = memberships.map((m) => {
      const org = memOrganisations.get(m.organisation_id);
      return org ? { ...org, role: m.role } : null;
    }).filter(Boolean);
    return { rows: orgs, rowCount: orgs.length };
  }

  if (norm.includes('update organisations set') && norm.includes('where id = $3')) {
    const name = params[0];
    const description = params[1];
    const id = params[2];
    const org = memOrganisations.get(id);
    if (org) {
      org.name = name;
      org.description = description;
      org.updated_at = new Date().toISOString();
      return { rows: [org], rowCount: 1 };
    }
    return { rows: [], rowCount: 0 };
  }

  if (norm.includes('delete from organisations where id = $1')) {
    const id = params[0];
    const deleted = memOrganisations.delete(id);
    // Cascade delete memberships, apps, etc.
    for (const [mId, m] of memMemberships.entries()) {
      if (m.organisation_id === id) memMemberships.delete(mId);
    }
    for (const [aId, a] of memApplications.entries()) {
      if (a.organisation_id === id) memApplications.delete(aId);
    }
    return { rows: [], rowCount: deleted ? 1 : 0 };
  }

  // Stage 7: Memberships
  if (norm.includes('insert into organisation_memberships')) {
    const organisation_id = params[0];
    const operator_id = params[1];
    const role = params[2];

    for (const m of memMemberships.values()) {
      if (m.organisation_id === organisation_id && m.operator_id === operator_id) {
        const error: any = new Error('duplicate key value violates unique constraint "organisation_memberships_unique"');
        error.code = '23505';
        throw error;
      }
    }

    const newMem: OrgMembershipRecord = {
      id: crypto.randomUUID(),
      organisation_id,
      operator_id,
      role,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };
    memMemberships.set(newMem.id, newMem);
    return { rows: [newMem], rowCount: 1 };
  }

  if (norm.includes('select') && norm.includes('from organisation_memberships') && norm.includes('where organisation_id = $1 and operator_id = $2')) {
    const orgId = params[0];
    const opId = params[1];
    const found = Array.from(memMemberships.values()).find(
      (m) => m.organisation_id === orgId && m.operator_id === opId
    );
    return { rows: found ? [found] : [], rowCount: found ? 1 : 0 };
  }

  if (norm.includes('select') && norm.includes('from organisation_memberships m join operators op') && norm.includes('where m.organisation_id = $1')) {
    const orgId = params[0];
    const list = Array.from(memMemberships.values())
      .filter((m) => m.organisation_id === orgId)
      .map((m) => {
        const op = memOperators.get(m.operator_id);
        return {
          id: m.id,
          organisation_id: m.organisation_id,
          operator_id: m.operator_id,
          role: m.role,
          created_at: m.created_at,
          username: op?.username || 'unknown',
          email: op?.email || 'unknown',
        };
      });
    return { rows: list, rowCount: list.length };
  }

  if (norm.includes('delete from organisation_memberships where organisation_id = $1')) {
    const orgId = params[0];
    const targetId = params[1];
    for (const [key, mem] of memMemberships.entries()) {
      if (mem.organisation_id === orgId && (mem.id === targetId || mem.operator_id === targetId)) {
        memMemberships.delete(key);
        return { rows: [], rowCount: 1 };
      }
    }
    return { rows: [], rowCount: 0 };
  }

  // Stage 7: Applications
  if (norm.includes('insert into applications')) {
    const organisation_id = params[0];
    const display_name = params[1];
    const environment = params[2];
    const approved_domain = params[3].toLowerCase();
    const configured_origin = params[4];
    const created_by = params[5] || null;

    for (const app of memApplications.values()) {
      if (app.organisation_id === organisation_id && app.approved_domain.toLowerCase() === approved_domain) {
        const error: any = new Error('duplicate key value violates unique constraint "applications_domain_unique"');
        error.code = '23505';
        throw error;
      }
    }

    const newApp: ApplicationRecord = {
      id: crypto.randomUUID(),
      organisation_id,
      display_name,
      environment,
      approved_domain,
      configured_origin,
      verification_status: 'unverified',
      activation_status: 'inactive',
      created_by,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };
    memApplications.set(newApp.id, newApp);
    return { rows: [newApp], rowCount: 1 };
  }

  if (norm.includes('select') && norm.includes('from applications') && norm.includes('where organisation_id = $1') && !norm.includes('and id = $2')) {
    const orgId = params[0];
    const list = Array.from(memApplications.values())
      .filter((a) => a.organisation_id === orgId)
      .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());
    return { rows: list, rowCount: list.length };
  }

  if (norm.includes('select') && norm.includes('from applications') && norm.includes('where id = $1 and organisation_id = $2')) {
    const id = params[0];
    const orgId = params[1];
    const app = memApplications.get(id);
    if (app && app.organisation_id === orgId) {
      return { rows: [app], rowCount: 1 };
    }
    return { rows: [], rowCount: 0 };
  }

  if (norm.includes('select') && norm.includes('from applications') && norm.includes('where approved_domain = $1')) {
    const domain = (params[0] || '').toLowerCase();
    const app = Array.from(memApplications.values()).find((a) => a.approved_domain.toLowerCase() === domain);
    return { rows: app ? [app] : [], rowCount: app ? 1 : 0 };
  }

  if (norm.includes('select') && norm.includes('from applications') && norm.includes('where configured_origin = $1 and organisation_id != $2')) {
    const origin = params[0];
    const orgId = params[1];
    const app = Array.from(memApplications.values()).find(
      (a) => a.configured_origin === origin && a.organisation_id !== orgId
    );
    return { rows: app ? [app] : [], rowCount: app ? 1 : 0 };
  }

  if (norm.includes('update applications set display_name = $1')) {
    const display_name = params[0];
    const environment = params[1];
    const configured_origin = params[2];
    const id = params[3];
    const orgId = params[4];
    const app = memApplications.get(id);
    if (app && app.organisation_id === orgId) {
      app.display_name = display_name;
      app.environment = environment;
      app.configured_origin = configured_origin;
      app.updated_at = new Date().toISOString();
      return { rows: [app], rowCount: 1 };
    }
    return { rows: [], rowCount: 0 };
  }

  if (norm.includes('update applications set verification_status = \'verified\'') || norm.includes('update applications set verification_status = $1')) {
    const isLit = norm.includes("verification_status = 'verified'");
    const vStatus = isLit ? 'verified' : params[0];
    const id = isLit ? params[0] : params[1];
    const orgId = isLit ? params[1] : params[2];
    const app = memApplications.get(id);
    if (app && app.organisation_id === orgId) {
      app.verification_status = vStatus as any;
      app.updated_at = new Date().toISOString();
      return { rows: [app], rowCount: 1 };
    }
    return { rows: [], rowCount: 0 };
  }

  if (norm.includes('update applications set verification_status = $1, activation_status = $2')) {
    const vStatus = params[0];
    const aStatus = params[1];
    const id = params[2];
    const orgId = params[3];
    const app = memApplications.get(id);
    if (app && app.organisation_id === orgId) {
      app.verification_status = vStatus;
      app.activation_status = aStatus;
      app.updated_at = new Date().toISOString();
      return { rows: [app], rowCount: 1 };
    }
    return { rows: [], rowCount: 0 };
  }

  if (norm.includes('update applications set activation_status = $1')) {
    const aStatus = params[0];
    const id = params[1];
    const orgId = params[2];
    const app = memApplications.get(id);
    if (app && app.organisation_id === orgId) {
      app.activation_status = aStatus;
      app.updated_at = new Date().toISOString();
      return { rows: [app], rowCount: 1 };
    }
    return { rows: [], rowCount: 0 };
  }

  if (norm.includes('delete from applications where id = $1 and organisation_id = $2')) {
    const id = params[0];
    const orgId = params[1];
    const app = memApplications.get(id);
    if (app && app.organisation_id === orgId) {
      memApplications.delete(id);
      return { rows: [], rowCount: 1 };
    }
    return { rows: [], rowCount: 0 };
  }

  // Stage 7: Domain Verifications
  if (norm.includes('insert into domain_verifications')) {
    const application_id = params[0];
    const organisation_id = params[1];
    const domain = params[2];
    const token = params[3];
    const record_name = params[4];
    const record_type = params[5] || 'TXT';
    const expires_at = params[6];

    const newDv: DomainVerificationRecord = {
      id: crypto.randomUUID(),
      application_id,
      organisation_id,
      domain,
      token,
      record_name,
      record_type: 'TXT',
      status: 'pending',
      expires_at,
      attempts_count: 0,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };
    memVerifications.set(newDv.id, newDv);
    return { rows: [newDv], rowCount: 1 };
  }

  if (norm.includes('select') && norm.includes('from domain_verifications') && norm.includes('where id = $1 and application_id = $2 and organisation_id = $3')) {
    const id = params[0];
    const appId = params[1];
    const orgId = params[2];
    const v = memVerifications.get(id);
    if (v && v.application_id === appId && v.organisation_id === orgId) {
      return { rows: [v], rowCount: 1 };
    }
    return { rows: [], rowCount: 0 };
  }

  if (norm.includes('select') && norm.includes('from domain_verifications') && norm.includes('where application_id = $1 and organisation_id = $2')) {
    const appId = params[0];
    const orgId = params[1];
    const list = Array.from(memVerifications.values())
      .filter((v) => v.application_id === appId && v.organisation_id === orgId)
      .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());
    return { rows: list, rowCount: list.length };
  }

  if (norm.includes('update domain_verifications') && norm.includes("set status = 'verified'")) {
    const verified_at = params[0];
    const id = params[1];
    const v = memVerifications.get(id);
    if (v) {
      v.status = 'verified';
      v.verified_at = verified_at;
      v.last_error = undefined;
      v.attempts_count += 1;
      v.updated_at = new Date().toISOString();
      return { rows: [v], rowCount: 1 };
    }
    return { rows: [], rowCount: 0 };
  }

  if (norm.includes('update domain_verifications set status = $1, verified_at = $2')) {
    const status = params[0];
    const verified_at = params[1];
    const last_error = params[2];
    const id = params[3];
    const v = memVerifications.get(id);
    if (v) {
      v.status = status;
      v.verified_at = verified_at;
      v.last_error = last_error;
      v.attempts_count += 1;
      v.updated_at = new Date().toISOString();
      return { rows: [v], rowCount: 1 };
    }
    return { rows: [], rowCount: 0 };
  }

  if (norm.includes('update domain_verifications set attempts_count = attempts_count + 1')) {
    const last_error = params[0];
    const id = params[1];
    const v = memVerifications.get(id);
    if (v) {
      v.attempts_count += 1;
      v.last_error = last_error;
      v.updated_at = new Date().toISOString();
      return { rows: [v], rowCount: 1 };
    }
    return { rows: [], rowCount: 0 };
  }

  // Stage 7: Application Protections
  if (norm.includes('insert into application_protections') || (norm.includes('application_protections') && norm.includes('on conflict'))) {
    const application_id = params[0];
    const organisation_id = params[1];
    const routing_mode = params[2] || 'shadow';
    const deception_threshold = params[3] !== undefined ? parseFloat(params[3]) : 0.70;
    const emergency_disable = params[4] || false;
    const quarantine_on_failure = params[5] !== undefined ? params[5] : true;

    const existing = Array.from(memProtections.values()).find((p) => p.application_id === application_id);
    if (existing) {
      existing.routing_mode = routing_mode;
      existing.deception_threshold = deception_threshold;
      existing.emergency_disable = emergency_disable;
      existing.quarantine_on_failure = quarantine_on_failure;
      existing.updated_at = new Date().toISOString();
      return { rows: [existing], rowCount: 1 };
    }

    const newProt: ApplicationProtectionRecord = {
      id: crypto.randomUUID(),
      application_id,
      organisation_id,
      routing_mode,
      deception_threshold,
      emergency_disable,
      quarantine_on_failure,
      updated_at: new Date().toISOString(),
    };
    memProtections.set(newProt.id, newProt);
    return { rows: [newProt], rowCount: 1 };
  }

  if (norm.includes('select') && norm.includes('from application_protections') && norm.includes('where application_id = $1 and organisation_id = $2')) {
    const appId = params[0];
    const orgId = params[1];
    const prot = Array.from(memProtections.values()).find(
      (p) => p.application_id === appId && p.organisation_id === orgId
    );
    return { rows: prot ? [prot] : [], rowCount: prot ? 1 : 0 };
  }

  if (norm.includes('update application_protections set routing_mode = $1')) {
    const routing_mode = params[0];
    const deception_threshold = parseFloat(params[1]);
    const emergency_disable = params[2];
    const quarantine_on_failure = params[3];
    const appId = params[4];
    const orgId = params[5];
    const prot = Array.from(memProtections.values()).find(
      (p) => p.application_id === appId && p.organisation_id === orgId
    );
    if (prot) {
      prot.routing_mode = routing_mode;
      prot.deception_threshold = deception_threshold;
      prot.emergency_disable = emergency_disable;
      prot.quarantine_on_failure = quarantine_on_failure;
      prot.updated_at = new Date().toISOString();
      return { rows: [prot], rowCount: 1 };
    }
    return { rows: [], rowCount: 0 };
  }

  // Stage 7: Organisation Audit Events
  if (norm.includes('insert into organisation_audit_events')) {
    const newOrgLog: OrgAuditEventRecord = {
      id: crypto.randomUUID(),
      organisation_id: params[0],
      actor_id: params[1],
      actor_username: params[2],
      action: params[3],
      resource_type: params[4],
      resource_id: params[5],
      status: params[6],
      ip_address: params[7],
      details: typeof params[8] === 'string' ? JSON.parse(params[8]) : params[8] || {},
      created_at: new Date().toISOString(),
    };
    memOrgAuditEvents.push(newOrgLog);
    return { rows: [newOrgLog], rowCount: 1 };
  }

  if (norm.includes('select') && norm.includes('from organisation_audit_events') && norm.includes('where organisation_id = $1')) {
    const orgId = params[0];
    const filtered = memOrgAuditEvents
      .filter((l) => l.organisation_id === orgId)
      .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());
    return { rows: filtered, rowCount: filtered.length };
  }

  // Stage 8: Security Events Pipeline
  if (norm.includes('insert into security_events')) {
    const newEvent: SecurityEventRecord = {
      id: crypto.randomUUID(),
      request_id: params[0],
      session_id: params[1],
      organisation_id: params[2] || undefined,
      application_id: params[3] || undefined,
      timestamp: params[4] || new Date().toISOString(),
      method: params[5],
      path: params[6],
      status_code: parseInt(params[7], 10),
      duration_ms: parseFloat(params[8]),
      detection_score: params[9] !== undefined && params[9] !== null ? parseFloat(params[9]) : undefined,
      detection_classification: params[10] || undefined,
      detection_latency_ms: params[11] !== undefined && params[11] !== null ? parseFloat(params[11]) : undefined,
      routing_decision: params[12] || 'ORIGIN',
      routing_reason: params[13] || 'UNKNOWN',
      routing_mode: params[14] || 'shadow',
      deception_node: params[15] || undefined,
      deception_strategy: params[16] || undefined,
      failure_quarantined: Boolean(params[17]),
      client_ip: params[18] || 'unknown',
      metadata: typeof params[19] === 'string' ? JSON.parse(params[19]) : params[19] || {},
      created_at: new Date().toISOString(),
    };
    memSecurityEvents.push(newEvent);
    return { rows: [newEvent], rowCount: 1 };
  }

  if (norm.includes('select') && norm.includes('from security_events')) {
    let filtered = [...memSecurityEvents];
    if (norm.includes('where organisation_id = $1') || norm.includes('organisation_id = $1')) {
      const orgId = params[0];
      filtered = filtered.filter((e) => e.organisation_id === orgId);
    }
    filtered.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
    return { rows: filtered, rowCount: filtered.length };
  }

  // Platform Admin queries (in-memory test support)
  if (norm.includes('select count(*)') && norm.includes('from organisations')) {
    return { rows: [{ count: memOrganisations.size }], rowCount: 1 };
  }
  if (norm.includes('select count(*)') && norm.includes('from applications')) {
    if (norm.includes("activation_status = 'active'")) {
      const activeCount = Array.from(memApplications.values()).filter(a => a.activation_status === 'active').length;
      return { rows: [{ count: activeCount }], rowCount: 1 };
    }
    if (norm.includes("verification_status = 'verified'")) {
      const verifiedCount = Array.from(memApplications.values()).filter(a => a.verification_status === 'verified').length;
      return { rows: [{ count: verifiedCount }], rowCount: 1 };
    }
    return { rows: [{ count: memApplications.size }], rowCount: 1 };
  }
  if (norm.includes('select count(*)') && norm.includes('from operators')) {
    return { rows: [{ count: memOperators.size }], rowCount: 1 };
  }
  if (norm.includes('select count(*)') && norm.includes('from security_events')) {
    return { rows: [{ count: memSecurityEvents.length }], rowCount: 1 };
  }
  if (norm.includes('select') && norm.includes('from organisations') && !norm.includes('where m.operator_id') && !norm.includes('where id = $1')) {
    const orgs = Array.from(memOrganisations.values()).map(o => {
      const appCount = Array.from(memApplications.values()).filter(a => a.organisation_id === o.id).length;
      const memberCount = Array.from(memMemberships.values()).filter(m => m.organisation_id === o.id).length;
      return { ...o, applications_count: appCount, members_count: memberCount };
    });
    return { rows: orgs, rowCount: orgs.length };
  }
  if (norm.includes('select') && norm.includes('from applications') && !norm.includes('where organisation_id = $1') && !norm.includes('where id = $1')) {
    const apps = Array.from(memApplications.values()).map(a => {
      const org = memOrganisations.get(a.organisation_id);
      return { ...a, organisation_name: org?.name || 'Unknown' };
    });
    return { rows: apps, rowCount: apps.length };
  }
  if (norm.includes('select') && norm.includes('from operators') && !norm.includes('where username') && !norm.includes('where id = $1')) {
    const ops = Array.from(memOperators.values()).map(op => {
      const orgCount = Array.from(memMemberships.values()).filter(m => m.operator_id === op.id).length;
      return {
        id: op.id,
        username: op.username,
        email: op.email,
        role: op.role,
        is_active: op.is_active,
        created_at: op.created_at,
        organisations_count: orgCount,
      };
    });
    return { rows: ops, rowCount: ops.length };
  }
  if (norm.includes('update operators set role = $1') && norm.includes('where id = $2')) {
    const newRole = params[0];
    const opId = params[1];
    const op = memOperators.get(opId);
    if (op) {
      op.role = newRole;
      op.updated_at = new Date().toISOString();
      return {
        rows: [{
          id: op.id,
          username: op.username,
          email: op.email,
          role: op.role,
          is_active: op.is_active,
          updated_at: op.updated_at,
        }],
        rowCount: 1,
      };
    }
    return { rows: [], rowCount: 0 };
  }

  return { rows: [], rowCount: 0 };
}

export function clearInMemoryDb(): void {
  memOperators.clear();
  memAuditLogs.length = 0;
  memSessions.clear();
  memOrganisations.clear();
  memMemberships.clear();
  memApplications.clear();
  memVerifications.clear();
  memProtections.clear();
  memOrgAuditEvents.length = 0;
  memSecurityEvents.length = 0;
}

export async function closeDb(): Promise<void> {
  if (pool) {
    await pool.end().catch(() => {});
    pool = null;
  }
}
