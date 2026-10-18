import assert from 'node:assert';
import { describe, it } from 'node:test';
import request from 'supertest';
import { createApp } from './app';
import { executeTransition, validateTransition } from './dsg';
import { PROTECTED_POLICY, validateStrategyAction } from './policy';
import { InMemorySessionStore } from './sessionStore';
import { applyDeceptionStrategy, selectDeceptionStrategy } from './strategy';
import { SYNTHETIC_ACCOUNTS } from './syntheticData';
import { DeceptionStrategyAction } from './types';

describe('Stage 4: Isolated Dynamic Deception Runtime & DSG Acceptance Tests', () => {
  const store = new InMemorySessionStore(50, 1000); // 1000ms TTL for testing
  const app = createApp(store, {
    maxRequestBodySize: 1024, // 1KB for testing payload limits
    sessionTtlMs: 1000,
  });

  describe('1. Runtime Lifecycle & Health Check', () => {
    it('GET /health returns HTTP 200 with valid healthy JSON and runtime metrics', async () => {
      const res = await request(app).get('/health');
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.body.status, 'healthy');
      assert.strictEqual(res.body.service, 'deception-runtime');
      assert.strictEqual(res.body.stage, 'Stage 4 — Dynamic Deception Runtime and DSG');
      assert.strictEqual(res.body.policyVersion, '1.0.0-immutable');
      assert.ok(typeof res.body.uptime === 'number');
      assert.ok(typeof res.body.activeSessions === 'number');
    });
  });

  describe('2. Synthetic APIs & Schema Validity', () => {
    it('GET /api/catalog returns schema-valid synthetic services', async () => {
      const res = await request(app).get('/api/catalog');
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.body.service, 'catalog');
      assert.ok(Array.isArray(res.body.services));
      assert.ok(res.body.totalCount > 0);
      assert.ok(res.headers['x-session-id']);
      assert.strictEqual(res.headers['x-dsg-current-node'], 'catalog');

      // Verify schema of first service
      const srv = res.body.services[0];
      assert.ok(srv.id);
      assert.ok(srv.name);
      assert.ok(srv.endpoint);
      assert.ok(srv.status);
    });

    it('GET /api/users returns schema-valid synthetic users (no real personal data)', async () => {
      const res = await request(app).get('/api/users');
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.body.service, 'user_directory');
      assert.ok(Array.isArray(res.body.users));

      // Verify synthetic privacy
      for (const user of res.body.users) {
        assert.ok(user.id.startsWith('usr-syn-'));
        assert.ok(user.email.endsWith('@synthetic.local'), 'Emails must be strictly synthetic');
        assert.ok(!user.password, 'Passwords must never be exposed');
      }
    });

    it('GET /api/files returns schema-valid synthetic file metadata (no host files)', async () => {
      const res = await request(app).get('/api/files');
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.body.service, 'file_store');
      assert.ok(Array.isArray(res.body.files));

      for (const file of res.body.files) {
        assert.ok(file.id);
        assert.ok(file.filename);
        assert.ok(file.sizeBytes > 0);
        assert.ok(file.checksumSha256);
        // Guarantee no local filesystem paths
        assert.ok(!file.path.startsWith('/Users/'), 'Cannot expose host paths');
        assert.ok(!file.path.startsWith('/home/'), 'Cannot expose host paths');
      }
    });

    it('POST /api/auth/login validates credentials with synthetic accounts', async () => {
      // 1. Invalid credentials -> 401
      const failRes = await request(app)
        .post('/api/auth/login')
        .send({ username: 'admin', password: 'WrongPassword!' });
      assert.strictEqual(failRes.status, 401);
      assert.strictEqual(failRes.body.code, 'INVALID_CREDENTIALS');

      // 2. Missing fields -> 400
      const missingRes = await request(app).post('/api/auth/login').send({});
      assert.strictEqual(missingRes.status, 400);
      assert.strictEqual(missingRes.body.code, 'MISSING_CREDENTIALS');

      // 3. Valid synthetic credentials -> 200
      const successRes = await request(app)
        .post('/api/auth/login')
        .send({ username: SYNTHETIC_ACCOUNTS[0].username, password: SYNTHETIC_ACCOUNTS[0].passwordHash });
      assert.strictEqual(successRes.status, 200);
      assert.strictEqual(successRes.body.status, 'authenticated');
      assert.strictEqual(successRes.body.user.role, 'admin');
      assert.ok(successRes.body.token.startsWith('syn_tok_'));
    });
  });

  describe('3. Session Isolation & Consistency', () => {
    it('Maintains consistent state across repeated requests within the same session', async () => {
      const sessionId = 'sess_test_consistency_1001';

      // 1. Initial request establishes session
      const res1 = await request(app).get('/api/catalog').set('X-Session-ID', sessionId);
      assert.strictEqual(res1.body.sessionId, sessionId);

      // 2. Second request reuses identical session
      const res2 = await request(app).get('/api/catalog').set('X-Session-ID', sessionId);
      assert.strictEqual(res2.body.sessionId, sessionId);
      assert.strictEqual(res2.body.totalCount, res1.body.totalCount);
    });

    it('Guarantees strict isolation: Separate sessions cannot read or mutate each other', async () => {
      const sessionA = 'sess_tenant_alpha_2001';
      const sessionB = 'sess_tenant_bravo_2002';

      // Session A logs in as admin
      const loginA = await request(app)
        .post('/api/auth/login')
        .set('X-Session-ID', sessionA)
        .send({ username: 'admin', password: 'P@ssw0rd2026!' });
      assert.strictEqual(loginA.status, 200);

      // Session A can now access /api/admin
      const adminA = await request(app).get('/api/admin').set('X-Session-ID', sessionA);
      assert.strictEqual(adminA.status, 200);
      assert.strictEqual(adminA.body.service, 'admin_console');

      // Session B has NOT authenticated: /api/admin MUST return 401
      const adminB = await request(app).get('/api/admin').set('X-Session-ID', sessionB);
      assert.strictEqual(adminB.status, 401);
      assert.strictEqual(adminB.body.code, 'ADMIN_AUTH_REQUIRED');

      // Session A probes files triggering decoy injection
      const filesA = await request(app).get('/api/files').set('X-Session-ID', sessionA);
      assert.ok(filesA.body.files.some((f: any) => f.isDecoy));

      // Session B's files must NOT contain Session A's newly injected decoy
      const rawSessionB = store.getSession(sessionB);
      assert.ok(rawSessionB);
      assert.strictEqual(rawSessionB.dynamicFiles.some((f) => f.isDecoy), false);
    });
  });

  describe('4. Deception State Graph (DSG) Transitions & Protected Policy', () => {
    it('Valid DSG transitions navigate nodes and update observation layer', () => {
      const session = store.createSession('sess_dsg_nav_3001');
      assert.strictEqual(session.currentNode, 'entrypoint');

      // Valid transition: entrypoint -> files
      const t1 = executeTransition(session, 'files');
      assert.strictEqual(t1.success, true);
      assert.strictEqual(session.currentNode, 'files');
      assert.ok(session.visitedNodes.includes('files'));

      // Valid transition: files -> admin
      const t2 = executeTransition(session, 'admin');
      assert.strictEqual(t2.success, true);
      assert.strictEqual(session.currentNode, 'admin');
      assert.ok(session.visitedNodes.includes('admin'));
    });

    it('Rejects invalid transitions and navigation to non-existent nodes', () => {
      const session = store.createSession('sess_dsg_nav_3002');

      // Invalid transition: non-existent node
      const tInvalid = executeTransition(session, 'unauthorized_hacked_node' as any);
      assert.strictEqual(tInvalid.success, false);
      assert.strictEqual(session.currentNode, 'entrypoint'); // Unchanged
    });

    it('Protected Policy Layer is strictly immutable and cannot be tampered with', () => {
      assert.strictEqual(Object.isFrozen(PROTECTED_POLICY), true);
      assert.strictEqual(Object.isFrozen(PROTECTED_POLICY.allowedNodes), true);
      assert.strictEqual(Object.isFrozen(PROTECTED_POLICY.allowedStrategyActions), true);
      assert.strictEqual(Object.isFrozen(PROTECTED_POLICY.safetyConstraints), true);

      assert.throws(() => {
        'use strict';
        (PROTECTED_POLICY as any).version = 'hacked';
      }, /Cannot assign to read only property/);
    });
  });

  describe('5. Controlled Deception Strategy Selector', () => {
    it('Selects actions strictly from the Protected Policy allowlist', () => {
      const session = store.createSession('sess_strategy_4001');

      // Probe files -> Proposes ADD_SYNTHETIC_DECOY_RECORD
      const actionFiles = selectDeceptionStrategy(session, {
        method: 'GET',
        path: '/api/files',
        statusCode: 200,
      });
      assert.strictEqual(actionFiles, 'ADD_SYNTHETIC_DECOY_RECORD');
      assert.strictEqual(validateStrategyAction(actionFiles), true);

      // Apply action
      const resApply = applyDeceptionStrategy(session, actionFiles);
      assert.strictEqual(resApply.applied, true);
      assert.ok(session.dynamicFiles.some((f) => f.isDecoy));

      // Repeated file query -> Maintains state because decoy already exists
      const nextAction = selectDeceptionStrategy(session, {
        method: 'GET',
        path: '/api/files',
        statusCode: 200,
      });
      assert.strictEqual(nextAction, 'MAINTAIN_CURRENT_STATE');
    });

    it('Escalates observation detail after repeated interactions', () => {
      const session = store.createSession('sess_strategy_4002');
      session.interactions = new Array(7).fill({
        timestamp: new Date().toISOString(),
        method: 'GET',
        path: '/api/users',
        targetNode: 'users',
        statusCode: 200,
        strategyExecuted: 'MAINTAIN_CURRENT_STATE' as DeceptionStrategyAction,
      });

      const action = selectDeceptionStrategy(session, {
        method: 'GET',
        path: '/api/users',
        statusCode: 200,
      });
      assert.strictEqual(action, 'INCREASE_OBSERVATION_DETAIL');

      applyDeceptionStrategy(session, action);
      assert.strictEqual(session.observationLevel, 'high_detail');
    });

    it('Rejects unauthorized or external strategy actions safely', () => {
      const session = store.createSession('sess_strategy_4003');
      const maliciousAction = 'EXECUTE_REMOTE_SHELL' as any;

      assert.strictEqual(validateStrategyAction(maliciousAction), false);
      const res = applyDeceptionStrategy(session, maliciousAction);
      assert.strictEqual(res.applied, false);
      assert.strictEqual(res.action, 'MAINTAIN_CURRENT_STATE');
    });
  });

  describe('6. Resource Limits & Session Eviction', () => {
    it('Rejects requests exceeding maxRequestBodySize with 413 Payload Too Large', async () => {
      const oversizedPayload = 'X'.repeat(2048); // limit is 1024 bytes
      const res = await request(app)
        .post('/api/auth/login')
        .send({ data: oversizedPayload });

      assert.strictEqual(res.status, 413);
      assert.strictEqual(res.body.error, 'Payload Too Large');
      assert.strictEqual(res.body.code, 'PAYLOAD_TOO_LARGE');
    });

    it('Evicts expired sessions according to session TTL', async () => {
      const ephemeralStore = new InMemorySessionStore(10, 50); // 50ms TTL
      const s = ephemeralStore.createSession('sess_ephemeral_5001');
      assert.ok(ephemeralStore.getSession('sess_ephemeral_5001'));

      // Wait 70ms for expiration
      await new Promise((resolve) => setTimeout(resolve, 70));

      // Expired session must return null
      assert.strictEqual(ephemeralStore.getSession('sess_ephemeral_5001'), null);
    });

    it('Enforces maxSessions limit with LRU capacity eviction', () => {
      const smallStore = new InMemorySessionStore(3, 60000); // Capacity 3
      smallStore.createSession('sess_cap_1');
      smallStore.createSession('sess_cap_2');
      smallStore.createSession('sess_cap_3');
      assert.strictEqual(smallStore.getActiveCount(), 3);

      // Creating 4th session evicts the oldest
      smallStore.createSession('sess_cap_4');
      assert.strictEqual(smallStore.getActiveCount(), 3);
      assert.strictEqual(smallStore.getSession('sess_cap_1'), null);
      assert.ok(smallStore.getSession('sess_cap_4'));
    });
  });

  describe('7. Negative Security & Error Handling', () => {
    it('Returns 404 with structured JSON for unknown endpoints', async () => {
      const res = await request(app).get('/api/non-existent-probe');
      assert.strictEqual(res.status, 404);
      assert.strictEqual(res.body.error, 'Not Found');
      assert.strictEqual(res.body.code, 'RESOURCE_NOT_FOUND');
    });

    it('Rejects path traversal probes with controlled 404/400 (never exposes host files)', async () => {
      const res = await request(app).get('/../../etc/passwd');
      assert.strictEqual(res.status, 404);
      assert.ok(typeof res.body.message === 'string');
      assert.ok(!res.text.includes('root:x:0:0'));
    });
  });
});
