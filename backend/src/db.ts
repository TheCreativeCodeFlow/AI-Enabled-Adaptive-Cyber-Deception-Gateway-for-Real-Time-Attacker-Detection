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

let pool: Pool | null = null;
let useInMemory = false;

// In-memory fallback stores for local testing without PostgreSQL
const memOperators = new Map<string, OperatorRecord>();
const memAuditLogs: AuditLogRecord[] = [];
const memSessions = new Map<string, OperatorSessionRecord>();

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

        CREATE INDEX IF NOT EXISTS idx_operators_username ON operators(username);
        CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at DESC);
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

  return { rows: [], rowCount: 0 };
}

export function clearInMemoryDb(): void {
  memOperators.clear();
  memAuditLogs.length = 0;
  memSessions.clear();
}

export async function closeDb(): Promise<void> {
  if (pool) {
    await pool.end().catch(() => {});
    pool = null;
  }
}
