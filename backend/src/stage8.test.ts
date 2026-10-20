import { describe, it, before, beforeEach } from 'node:test';
import assert from 'node:assert';
import request from 'supertest';
import { app } from './app';
import { clearInMemoryDb, setUseInMemory } from './db';
import { generateOperatorToken } from './auth';

describe('Stage 8: Security Event Pipeline & Tenant Isolation Tests', () => {
  let orgOwnerToken: string;
  let securityAdminToken: string;
  let securityAnalystToken: string;
  let otherOrgToken: string;

  let tenantAOrgId: string;
  let tenantBOrgId: string;
  let appAId: string;

  before(async () => {
    setUseInMemory(true);
  });

  async function registerAndLogin(username: string, email: string, role: 'admin' | 'analyst') {
    const reg = await request(app).post('/api/auth/register').send({
      username,
      email,
      password: 'SuperSecurePassword123!',
      role,
    });
    const login = await request(app).post('/api/auth/login').send({
      username,
      password: 'SuperSecurePassword123!',
    });
    return { id: reg.body.operator?.id, token: login.body.token };
  }

  beforeEach(async () => {
    clearInMemoryDb();

    // 1. Create Tenant A Owner
    const ownerA = await registerAndLogin('owner_a', 'owner_a@deception.local', 'admin');
    orgOwnerToken = ownerA.token;

    // 2. Create Tenant A
    const orgRes = await request(app)
      .post('/api/orgs')
      .set('Authorization', `Bearer ${orgOwnerToken}`)
      .send({
        name: 'Tenant Alpha Corp',
        slug: 'alpha-corp',
        description: 'First test organisation',
      });
    tenantAOrgId = orgRes.body.organisation.id;

    // 3. Create Tenant A Admin
    const adminA = await registerAndLogin('admin_a', 'admin_a@deception.local', 'admin');
    securityAdminToken = adminA.token;
    await request(app)
      .post(`/api/orgs/${tenantAOrgId}/members`)
      .set('Authorization', `Bearer ${orgOwnerToken}`)
      .send({
        username: 'admin_a',
        role: 'security_admin',
      });

    // 4. Create Tenant A Analyst
    const analystA = await registerAndLogin('analyst_a', 'analyst_a@deception.local', 'analyst');
    securityAnalystToken = analystA.token;
    await request(app)
      .post(`/api/orgs/${tenantAOrgId}/members`)
      .set('Authorization', `Bearer ${orgOwnerToken}`)
      .send({
        username: 'analyst_a',
        role: 'security_analyst',
      });

    // 5. Create Tenant B Operator (analyst role without global admin override)
    const userB = await registerAndLogin('user_b', 'user_b@deception.local', 'analyst');
    otherOrgToken = userB.token;

    // 6. Register Application in Tenant A
    const appRes = await request(app)
      .post(`/api/orgs/${tenantAOrgId}/apps`)
      .set('Authorization', `Bearer ${securityAdminToken}`)
      .send({
        displayName: 'Alpha Web Application',
        environment: 'production',
        approvedDomain: 'alpha.deception.local',
        configuredOrigin: 'http://test-origin:5000',
      });
    appAId = appRes.body.application.id;
  });

  // =========================================================================
  // 1. Security Event Ingestion & Redaction
  // =========================================================================
  describe('1. Security Event Ingestion & Redaction', () => {
    it('Ingests valid security event and persists it with sanitized parameters', async () => {
      const res = await request(app)
        .post('/api/events')
        .set('x-service-token', 'deception-gateway-internal-service-secret')
        .send({
          requestId: 'req_test_001',
          sessionId: 'sess_abc1234567890',
          organisationId: tenantAOrgId,
          applicationId: appAId,
          timestamp: new Date().toISOString(),
          method: 'GET',
          path: '/api/login?token=super_secret_token_12345&password=SuperSecretPassword!&user=victim',
          statusCode: 200,
          durationMs: 4.5,
          detectionScore: 0.12,
          detectionClassification: 'BENIGN',
          detectionLatencyMs: 1.5,
          routingDecision: 'ORIGIN',
          routingReason: 'BENIGN_EVALUATION',
          routingMode: 'active',
          failureQuarantined: false,
          clientIp: '192.168.1.100',
          metadata: {
            sensitivePassword: 'myRawPassword!',
            authToken: 'eyJhbGciOi...',
            regularField: 'safeValue',
          },
        });

      assert.strictEqual(res.status, 201);
      assert.strictEqual(res.body.status, 'recorded');
      const evt = res.body.event;
      assert.strictEqual(evt.request_id, 'req_test_001');
      assert.strictEqual(evt.session_id, 'sess_abc1234567890');
      assert.strictEqual(evt.routing_decision, 'ORIGIN');

      // Verify redaction in path
      assert.strictEqual(evt.path.includes('super_secret_token_12345'), false);
      assert.strictEqual(evt.path.includes('SuperSecretPassword!'), false);

      // Verify redaction in metadata
      const meta = typeof evt.metadata === 'string' ? JSON.parse(evt.metadata) : evt.metadata;
      assert.strictEqual(meta.sensitivePassword, '[REDACTED]');
      assert.strictEqual(meta.authToken, '[REDACTED]');
      assert.strictEqual(meta.regularField, 'safeValue');
    });

    it('Rejects malformed event payload missing required fields', async () => {
      const res = await request(app)
        .post('/api/events')
        .set('x-service-token', 'deception-gateway-internal-service-secret')
        .send({
          // Missing requestId, sessionId, method, path
          durationMs: 4.5,
        });

      assert.strictEqual(res.status, 400);
      assert.strictEqual(res.body.error, 'Bad Request');
    });
  });

  // =========================================================================
  // 2. Tenant Isolation & Cross-Tenant Access Defense (IDOR)
  // =========================================================================
  describe('2. Tenant Isolation & Cross-Tenant Access Defense', () => {
    beforeEach(async () => {
      // Ingest 2 events for Tenant A
      await request(app)
        .post('/api/events')
        .send({
          requestId: 'req_a_1',
          sessionId: 'sess_tenant_a_1',
          organisationId: tenantAOrgId,
          applicationId: appAId,
          method: 'GET',
          path: '/api/catalog',
          statusCode: 200,
          durationMs: 3.2,
          detectionScore: 0.05,
          detectionClassification: 'BENIGN',
          routingDecision: 'ORIGIN',
          routingReason: 'BENIGN',
          routingMode: 'active',
          clientIp: '127.0.0.1',
        });

      await request(app)
        .post('/api/events')
        .send({
          requestId: 'req_a_2',
          sessionId: 'sess_tenant_a_2',
          organisationId: tenantAOrgId,
          applicationId: appAId,
          method: 'GET',
          path: '/api/admin/probe',
          statusCode: 200,
          durationMs: 2.8,
          detectionScore: 0.95,
          detectionClassification: 'MALICIOUS',
          routingDecision: 'DECEPTION',
          routingReason: 'MALICIOUS',
          routingMode: 'active',
          clientIp: '127.0.0.1',
        });

      // Ingest 1 event for Tenant B
      await request(app)
        .post('/api/events')
        .send({
          requestId: 'req_b_1',
          sessionId: 'sess_tenant_b_1',
          organisationId: tenantBOrgId,
          method: 'GET',
          path: '/api/users',
          statusCode: 200,
          durationMs: 2.1,
          routingDecision: 'ORIGIN',
          routingReason: 'BENIGN',
          routingMode: 'active',
          clientIp: '127.0.0.1',
        });
    });

    it('Tenant A member can query Tenant A security events', async () => {
      const res = await request(app)
        .get(`/api/orgs/${tenantAOrgId}/events`)
        .set('Authorization', `Bearer ${securityAnalystToken}`);

      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.body.total, 2);
      assert.strictEqual(res.body.events.length, 2);
      for (const e of res.body.events) {
        assert.strictEqual(e.organisation_id, tenantAOrgId);
      }
    });

    it('Cross-Tenant IDOR: Operator from Tenant B CANNOT query Tenant A events (Access Denied / Not Found)', async () => {
      const res = await request(app)
        .get(`/api/orgs/${tenantAOrgId}/events`)
        .set('Authorization', `Bearer ${otherOrgToken}`);

      assert.strictEqual(res.status, 404);
      assert.strictEqual(res.body.error, 'Not Found');
    });

    it('Unauthenticated caller cannot query tenant security events (401 Unauthorized)', async () => {
      const res = await request(app).get(`/api/orgs/${tenantAOrgId}/events`);
      assert.strictEqual(res.status, 401);
    });

    it('Supports query filtering by routingDecision and pagination', async () => {
      const filteredRes = await request(app)
        .get(`/api/orgs/${tenantAOrgId}/events?routingDecision=DECEPTION`)
        .set('Authorization', `Bearer ${orgOwnerToken}`);

      assert.strictEqual(filteredRes.status, 200);
      assert.strictEqual(filteredRes.body.total, 1);
      assert.strictEqual(filteredRes.body.events[0].routing_decision, 'DECEPTION');
    });

    it('Supports query filtering by classification (Stage 7 Threat Detection)', async () => {
      const maliciousRes = await request(app)
        .get(`/api/orgs/${tenantAOrgId}/events?classification=MALICIOUS`)
        .set('Authorization', `Bearer ${orgOwnerToken}`);

      assert.strictEqual(maliciousRes.status, 200);
      assert.strictEqual(maliciousRes.body.total, 1);
      assert.strictEqual(maliciousRes.body.events[0].detection_classification, 'MALICIOUS');

      const benignRes = await request(app)
        .get(`/api/orgs/${tenantAOrgId}/events?classification=BENIGN`)
        .set('Authorization', `Bearer ${orgOwnerToken}`);

      assert.strictEqual(benignRes.status, 200);
      assert.strictEqual(benignRes.body.total, 1);
      assert.strictEqual(benignRes.body.events[0].detection_classification, 'BENIGN');
    });

    it('GET /api/orgs/:orgId/events/summary accurately aggregates tenant events metrics', async () => {
      const summaryRes = await request(app)
        .get(`/api/orgs/${tenantAOrgId}/events/summary`)
        .set('Authorization', `Bearer ${securityAdminToken}`);

      assert.strictEqual(summaryRes.status, 200);
      assert.strictEqual(summaryRes.body.organisationId, tenantAOrgId);
      const summary = summaryRes.body.summary;
      assert.strictEqual(summary.totalEvents, 2);
      assert.strictEqual(summary.decisions.ORIGIN, 1);
      assert.strictEqual(summary.decisions.DECEPTION, 1);
      assert.strictEqual(summary.classifications.MALICIOUS, 1);
      assert.strictEqual(summary.classifications.BENIGN, 1);
      assert.strictEqual(summary.quarantinedCount, 0);
      assert.ok(summary.avgDetectionScore > 0);
      assert.ok(summary.avgDurationMs > 0);
    });
  });
});
