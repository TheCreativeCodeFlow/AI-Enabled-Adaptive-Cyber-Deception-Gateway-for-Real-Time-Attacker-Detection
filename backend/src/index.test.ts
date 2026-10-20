import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import request from 'supertest';
import { app } from './app';
import { initDb, closeDb, query, clearInMemoryDb } from './db';

describe('Backend Health & Core Endpoints', () => {
  before(async () => {
    await initDb();
  });

  it('GET /health returns 200 and healthy status JSON', async () => {
    const response = await request(app).get('/health');
    assert.strictEqual(response.status, 200);
    assert.strictEqual(response.headers['content-type'].includes('application/json'), true);
    assert.strictEqual(response.body.status, 'healthy');
    assert.strictEqual(response.body.service, 'backend');
    assert.ok(typeof response.body.timestamp === 'string');
    assert.ok(typeof response.body.uptime === 'number');
  });

  it('GET / returns 200 with service metadata', async () => {
    const response = await request(app).get('/');
    assert.strictEqual(response.status, 200);
    assert.strictEqual(response.body.service, 'deception-gateway-backend');
    assert.strictEqual(response.body.healthCheck, '/health');
  });

  it('GET /non-existent returns 404', async () => {
    const response = await request(app).get('/non-existent');
    assert.strictEqual(response.status, 404);
    assert.strictEqual(response.body.error, 'Not Found');
  });
});

describe('Stage 6: Operator Authentication & RBAC', () => {
  before(async () => {
    await initDb();
    try {
      await query('DELETE FROM audit_logs');
      await query('DELETE FROM operator_sessions');
      await query('DELETE FROM operators');
    } catch {}
    clearInMemoryDb();
  });

  after(async () => {
    await closeDb();
  });
  const adminAccount = {
    username: 'sec_admin',
    email: 'admin@deception.local',
    password: 'SuperSecretAdminPassword123!',
    role: 'admin',
  };

  const analystAccount = {
    username: 'sec_analyst',
    email: 'analyst@deception.local',
    password: 'SuperSecretAnalystPassword123!',
    role: 'analyst',
  };

  let adminToken: string;
  let analystToken: string;

  it('1. Operator Registration: Successfully creates admin and analyst accounts', async () => {
    // Register Admin
    const adminRes = await request(app).post('/api/auth/register').send(adminAccount);
    assert.strictEqual(adminRes.status, 201);
    assert.strictEqual(adminRes.body.operator.username, 'sec_admin');
    assert.strictEqual(adminRes.body.operator.role, 'admin');
    assert.ok(adminRes.body.operator.permissions.includes('routing:control'));
    // Plaintext password MUST NOT be returned in response
    assert.strictEqual(adminRes.body.operator.password, undefined);
    assert.strictEqual(adminRes.body.operator.password_hash, undefined);

    // Register Analyst
    const analystRes = await request(app).post('/api/auth/register').send(analystAccount);
    assert.strictEqual(analystRes.status, 201);
    assert.strictEqual(analystRes.body.operator.username, 'sec_analyst');
    assert.strictEqual(analystRes.body.operator.role, 'analyst');
    assert.ok(!analystRes.body.operator.permissions.includes('routing:control'));
  });

  it('2. Registration Validation: Rejects duplicate usernames, invalid emails, and weak passwords', async () => {
    // Duplicate username
    const dupRes = await request(app).post('/api/auth/register').send(adminAccount);
    assert.strictEqual(dupRes.status, 409);

    // Short password
    const shortPassRes = await request(app).post('/api/auth/register').send({
      username: 'short_user',
      email: 'short@deception.local',
      password: '123',
    });
    assert.strictEqual(shortPassRes.status, 400);

    // Invalid email
    const badEmailRes = await request(app).post('/api/auth/register').send({
      username: 'bad_email_user',
      email: 'not-an-email',
      password: 'ValidPassword123!',
    });
    assert.strictEqual(badEmailRes.status, 400);
  });

  it('3. Operator Login: Issues signed JWT token for valid credentials', async () => {
    // Login as Admin
    const loginRes = await request(app).post('/api/auth/login').send({
      username: adminAccount.username,
      password: adminAccount.password,
    });
    assert.strictEqual(loginRes.status, 200);
    assert.ok(loginRes.body.token);
    assert.strictEqual(loginRes.body.user.username, 'sec_admin');
    assert.strictEqual(loginRes.body.user.role, 'admin');
    adminToken = loginRes.body.token;

    // Login as Analyst
    const analystLoginRes = await request(app).post('/api/auth/login').send({
      username: analystAccount.username,
      password: analystAccount.password,
    });
    assert.strictEqual(analystLoginRes.status, 200);
    assert.ok(analystLoginRes.body.token);
    assert.strictEqual(analystLoginRes.body.user.role, 'analyst');
    analystToken = analystLoginRes.body.token;
  });

  it('4. Operator Login Failure: Rejects bad password and unknown usernames', async () => {
    const badPassRes = await request(app).post('/api/auth/login').send({
      username: adminAccount.username,
      password: 'WrongPassword!',
    });
    assert.strictEqual(badPassRes.status, 401);

    const unknownUserRes = await request(app).post('/api/auth/login').send({
      username: 'non_existent_operator',
      password: 'SomePassword123!',
    });
    assert.strictEqual(unknownUserRes.status, 401);
  });

  it('5. Token Verification & Me Endpoint: Authenticates valid token and rejects unauthenticated request', async () => {
    // Unauthenticated
    const unauthRes = await request(app).get('/api/auth/me');
    assert.strictEqual(unauthRes.status, 401);

    // Authenticated with Admin Token
    const authRes = await request(app)
      .get('/api/auth/me')
      .set('Authorization', `Bearer ${adminToken}`);
    assert.strictEqual(authRes.status, 200);
    assert.strictEqual(authRes.body.operator.username, 'sec_admin');
    assert.strictEqual(authRes.body.operator.role, 'admin');
  });

  it('6. Audit Logging: Audit trail captures operator events', async () => {
    const auditRes = await request(app)
      .get('/api/audit/logs')
      .set('Authorization', `Bearer ${adminToken}`);
    assert.strictEqual(auditRes.status, 200);
    assert.ok(Array.isArray(auditRes.body.logs));
    assert.ok(auditRes.body.logs.length > 0);

    const actions = auditRes.body.logs.map((l: any) => l.action);
    assert.ok(actions.includes('OPERATOR_REGISTERED'));
    assert.ok(actions.includes('LOGIN_SUCCESS'));
  });

  it('7. Operator Logout: Terminates session', async () => {
    const logoutRes = await request(app)
      .post('/api/auth/logout')
      .set('Authorization', `Bearer ${adminToken}`);
    assert.strictEqual(logoutRes.status, 200);
    assert.strictEqual(logoutRes.body.status, 'logged_out');
  });

  it('8. Rate Limiting: Blocks IP/account after repeated consecutive failures', async () => {
    const bruteForceUsername = 'brute_force_target';
    // Register account
    await request(app).post('/api/auth/register').send({
      username: bruteForceUsername,
      email: 'brute@deception.local',
      password: 'TargetPassword123!',
    });

    // 5 consecutive failures
    for (let i = 0; i < 5; i++) {
      await request(app).post('/api/auth/login').send({
        username: bruteForceUsername,
        password: 'BadPassword',
      });
    }

    // 6th attempt should receive HTTP 429 Too Many Requests
    const rateLimitedRes = await request(app).post('/api/auth/login').send({
      username: bruteForceUsername,
      password: 'TargetPassword123!',
    });
    assert.strictEqual(rateLimitedRes.status, 429);
    assert.ok(rateLimitedRes.body.retryAfterSeconds);
  });
});

describe('Platform Administrator Console & API Access Control', () => {
  let adminToken: string;
  let analystToken: string;
  let testAnalystId: string;

  before(async () => {
    // Register Admin
    const adminRes = await request(app).post('/api/auth/register').send({
      username: 'platform_super_admin',
      email: 'superadmin@deception.local',
      password: 'AdminPassword123!',
      role: 'admin',
    });
    if (adminRes.status === 201) {
      const loginRes = await request(app).post('/api/auth/login').send({
        username: 'platform_super_admin',
        password: 'AdminPassword123!',
      });
      adminToken = loginRes.body.token;
    } else {
      const loginRes = await request(app).post('/api/auth/login').send({
        username: 'platform_super_admin',
        password: 'AdminPassword123!',
      });
      adminToken = loginRes.body.token;
    }

    // Register Analyst
    const analystRes = await request(app).post('/api/auth/register').send({
      username: 'platform_analyst_test',
      email: 'analyst_test@deception.local',
      password: 'AnalystPassword123!',
      role: 'analyst',
    });
    if (analystRes.status === 201) {
      testAnalystId = analystRes.body.operator.id;
      const loginRes = await request(app).post('/api/auth/login').send({
        username: 'platform_analyst_test',
        password: 'AnalystPassword123!',
      });
      analystToken = loginRes.body.token;
    } else {
      const loginRes = await request(app).post('/api/auth/login').send({
        username: 'platform_analyst_test',
        password: 'AnalystPassword123!',
      });
      analystToken = loginRes.body.token;
      testAnalystId = loginRes.body.user.id;
    }
  });

  it('1. Unauthenticated caller is rejected from /api/admin/overview with 401', async () => {
    const res = await request(app).get('/api/admin/overview');
    assert.strictEqual(res.status, 401);
    assert.strictEqual(res.body.error, 'Unauthorized');
  });

  it('2. Non-admin operator (analyst) is rejected from /api/admin/overview with 403 Forbidden', async () => {
    const res = await request(app)
      .get('/api/admin/overview')
      .set('Authorization', `Bearer ${analystToken}`);
    assert.strictEqual(res.status, 403);
    assert.strictEqual(res.body.error, 'Forbidden');
  });

  it('3. Platform Admin can query /api/admin/overview', async () => {
    const res = await request(app)
      .get('/api/admin/overview')
      .set('Authorization', `Bearer ${adminToken}`);
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.status, 'success');
    assert.ok(typeof res.body.platformOverview.totalOrganisations === 'number');
    assert.ok(typeof res.body.platformOverview.totalApplications === 'number');
    assert.ok(typeof res.body.platformOverview.totalOperators === 'number');
  });

  it('4. Platform Admin can list all platform organisations, applications, users and audit', async () => {
    const orgsRes = await request(app)
      .get('/api/admin/organisations')
      .set('Authorization', `Bearer ${adminToken}`);
    assert.strictEqual(orgsRes.status, 200);
    assert.ok(Array.isArray(orgsRes.body.organisations));

    const appsRes = await request(app)
      .get('/api/admin/applications')
      .set('Authorization', `Bearer ${adminToken}`);
    assert.strictEqual(appsRes.status, 200);
    assert.ok(Array.isArray(appsRes.body.applications));

    const usersRes = await request(app)
      .get('/api/admin/users')
      .set('Authorization', `Bearer ${adminToken}`);
    assert.strictEqual(usersRes.status, 200);
    assert.ok(Array.isArray(usersRes.body.users));

    const auditRes = await request(app)
      .get('/api/admin/audit')
      .set('Authorization', `Bearer ${adminToken}`);
    assert.strictEqual(auditRes.status, 200);
    assert.ok(Array.isArray(auditRes.body.logs));

    const healthRes = await request(app)
      .get('/api/admin/system/health')
      .set('Authorization', `Bearer ${adminToken}`);
    assert.strictEqual(healthRes.status, 200);
    assert.strictEqual(healthRes.body.status, 'healthy');
  });

  it('5. Admin cannot demote their own account to prevent lockouts', async () => {
    const meRes = await request(app)
      .get('/api/auth/me')
      .set('Authorization', `Bearer ${adminToken}`);
    const myId = meRes.body.operator.id;

    const demoteRes = await request(app)
      .put(`/api/admin/users/${myId}/role`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ role: 'analyst' });
    assert.strictEqual(demoteRes.status, 400);
    assert.strictEqual(demoteRes.body.error, 'Bad Request');
  });
});


