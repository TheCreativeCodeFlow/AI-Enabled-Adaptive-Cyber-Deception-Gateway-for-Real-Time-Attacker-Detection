import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import request from 'supertest';
import { app } from './app';
import { initDb, closeDb, query, clearInMemoryDb } from './db';
import { setMockDnsResolver } from './domainVerification';

describe('Stage 7: Multi-Tenant Organisation Management & Application Onboarding', () => {
  let userAToken: string;
  let userBToken: string;
  let userCToken: string;
  let userAId: string;
  let userBId: string;
  let userCId: string;

  let orgAId: string;
  let appAId: string;

  before(async () => {
    await initDb();
    try {
      await query('DELETE FROM organisation_audit_events');
      await query('DELETE FROM application_protections');
      await query('DELETE FROM domain_verifications');
      await query('DELETE FROM applications');
      await query('DELETE FROM organisation_memberships');
      await query('DELETE FROM organisations');
      await query('DELETE FROM audit_logs');
      await query('DELETE FROM operator_sessions');
      await query('DELETE FROM operators');
    } catch {}
    clearInMemoryDb();

    // Register User A (Org A Owner)
    const resA = await request(app).post('/api/auth/register').send({
      username: 'user_a',
      email: 'user_a@tenant-a.com',
      password: 'UserAPassword123!',
      role: 'admin',
    });
    userAId = resA.body.operator.id;

    const loginA = await request(app).post('/api/auth/login').send({
      username: 'user_a',
      password: 'UserAPassword123!',
    });
    userAToken = loginA.body.token;

    // Register User B (will be member of Org A with security_analyst role)
    const resB = await request(app).post('/api/auth/register').send({
      username: 'user_b',
      email: 'user_b@tenant-b.com',
      password: 'UserBPassword123!',
      role: 'analyst',
    });
    userBId = resB.body.operator.id;

    const loginB = await request(app).post('/api/auth/login').send({
      username: 'user_b',
      password: 'UserBPassword123!',
    });
    userBToken = loginB.body.token;

    // Register User C (will be member of Org A with security_admin role)
    const resC = await request(app).post('/api/auth/register').send({
      username: 'user_c',
      email: 'user_c@tenant-c.com',
      password: 'UserCPassword123!',
      role: 'analyst',
    });
    userCId = resC.body.operator.id;

    const loginC = await request(app).post('/api/auth/login').send({
      username: 'user_c',
      password: 'UserCPassword123!',
    });
    userCToken = loginC.body.token;
  });

  after(async () => {
    // Reset mock DNS resolver
    setMockDnsResolver(null);
    await closeDb();
  });

  // 1. Organisation Creation & Ownership
  it('1. Organisation Creation: Creates organisation and assigns creator as org_owner', async () => {
    const res = await request(app)
      .post('/api/orgs')
      .set('Authorization', `Bearer ${userAToken}`)
      .send({
        name: 'Acme Cyber Corp',
        slug: 'acme-corp',
        description: 'Enterprise Tenant Acme',
      });

    assert.strictEqual(res.status, 201);
    assert.strictEqual(res.body.organisation.name, 'Acme Cyber Corp');
    assert.strictEqual(res.body.organisation.slug, 'acme-corp');
    assert.strictEqual(res.body.organisation.role, 'org_owner');
    orgAId = res.body.organisation.id;
    assert.ok(orgAId);

    // List organisations for User A
    const listRes = await request(app)
      .get('/api/orgs')
      .set('Authorization', `Bearer ${userAToken}`);
    assert.strictEqual(listRes.status, 200);
    assert.strictEqual(listRes.body.organisations.length, 1);
    assert.strictEqual(listRes.body.organisations[0].id, orgAId);

    // User B should see 0 organisations initially
    const listBRes = await request(app)
      .get('/api/orgs')
      .set('Authorization', `Bearer ${userBToken}`);
    assert.strictEqual(listBRes.status, 200);
    assert.strictEqual(listBRes.body.organisations.length, 0);
  });

  // 2. Cross-Tenant Isolation / IDOR Prevention
  it('2. Cross-Tenant IDOR: Non-member cannot view or manipulate another organisation', async () => {
    // User B tries to view Org A
    const getRes = await request(app)
      .get(`/api/orgs/${orgAId}`)
      .set('Authorization', `Bearer ${userBToken}`);
    assert.strictEqual(getRes.status, 404);

    // User B tries to view members of Org A
    const memRes = await request(app)
      .get(`/api/orgs/${orgAId}/members`)
      .set('Authorization', `Bearer ${userBToken}`);
    assert.strictEqual(memRes.status, 404);

    // User B tries to view audit events of Org A
    const auditRes = await request(app)
      .get(`/api/orgs/${orgAId}/audit`)
      .set('Authorization', `Bearer ${userBToken}`);
    assert.strictEqual(auditRes.status, 404);

    // User B tries to list apps in Org A
    const appsRes = await request(app)
      .get(`/api/orgs/${orgAId}/apps`)
      .set('Authorization', `Bearer ${userBToken}`);
    assert.strictEqual(appsRes.status, 404);

    // User B tries to register app in Org A
    const postAppRes = await request(app)
      .post(`/api/orgs/${orgAId}/apps`)
      .set('Authorization', `Bearer ${userBToken}`)
      .send({
        displayName: 'Hacked App',
        approvedDomain: 'hacked.com',
        configuredOrigin: 'https://hacked.com',
      });
    assert.strictEqual(postAppRes.status, 404);
  });

  // 3. Member Management & Permissions Assignment
  it('3. Member Management: Org Owner invites security_admin and security_analyst', async () => {
    // Add User B as security_analyst
    const addB = await request(app)
      .post(`/api/orgs/${orgAId}/members`)
      .set('Authorization', `Bearer ${userAToken}`)
      .send({
        operatorId: userBId,
        role: 'security_analyst',
      });
    assert.strictEqual(addB.status, 201);
    assert.strictEqual(addB.body.member.role, 'security_analyst');

    // Add User C as security_admin
    const addC = await request(app)
      .post(`/api/orgs/${orgAId}/members`)
      .set('Authorization', `Bearer ${userAToken}`)
      .send({
        operatorId: userCId,
        role: 'security_admin',
      });
    assert.strictEqual(addC.status, 201);
    assert.strictEqual(addC.body.member.role, 'security_admin');

    // Check members list
    const membersRes = await request(app)
      .get(`/api/orgs/${orgAId}/members`)
      .set('Authorization', `Bearer ${userAToken}`);
    assert.strictEqual(membersRes.status, 200);
    assert.strictEqual(membersRes.body.members.length, 3);
  });

  // 4. Origin & Domain Validation (SSRF Prevention)
  it('4. SSRF & Origin Validation: Rejects cloud metadata, link-local, credentials and cross-tenant origins', async () => {
    // Cloud metadata IP
    const metaIpRes = await request(app)
      .post(`/api/orgs/${orgAId}/apps`)
      .set('Authorization', `Bearer ${userAToken}`)
      .send({
        displayName: 'SSRF Cloud Meta Test',
        approvedDomain: 'test.acme.com',
        configuredOrigin: 'http://169.254.169.254/latest/meta-data',
      });
    assert.strictEqual(metaIpRes.status, 400);
    assert.ok(metaIpRes.body.message.includes('metadata'));

    // Cloud metadata hostname
    const metaHostRes = await request(app)
      .post(`/api/orgs/${orgAId}/apps`)
      .set('Authorization', `Bearer ${userAToken}`)
      .send({
        displayName: 'SSRF Cloud Host Test',
        approvedDomain: 'test.acme.com',
        configuredOrigin: 'http://metadata.google.internal/computeMetadata/v1/',
      });
    assert.strictEqual(metaHostRes.status, 400);

    // Embedded user credentials in origin URL
    const credRes = await request(app)
      .post(`/api/orgs/${orgAId}/apps`)
      .set('Authorization', `Bearer ${userAToken}`)
      .send({
        displayName: 'Credentials Test',
        approvedDomain: 'test.acme.com',
        configuredOrigin: 'https://admin:secret123@api.acme.com',
      });
    assert.strictEqual(credRes.status, 400);
    assert.ok(credRes.body.message.includes('credentials'));

    // Invalid domain format
    const badDomainRes = await request(app)
      .post(`/api/orgs/${orgAId}/apps`)
      .set('Authorization', `Bearer ${userAToken}`)
      .send({
        displayName: 'Bad Domain Test',
        approvedDomain: 'invalid_domain_with_underscores',
        configuredOrigin: 'https://api.acme.com',
      });
    assert.strictEqual(badDomainRes.status, 400);
  });

  // 5. Application Registration
  it('5. Application Registration: Registers application with unverified initial state and pending challenge', async () => {
    const regRes = await request(app)
      .post(`/api/orgs/${orgAId}/apps`)
      .set('Authorization', `Bearer ${userAToken}`)
      .send({
        displayName: 'Acme Main Customer Portal',
        environment: 'production',
        approvedDomain: 'portal.acme.com',
        configuredOrigin: 'https://app-origin.acme.internal:8443',
      });

    assert.strictEqual(regRes.status, 201);
    const appData = regRes.body.application;
    assert.strictEqual(appData.display_name, 'Acme Main Customer Portal');
    assert.strictEqual(appData.approved_domain, 'portal.acme.com');
    assert.strictEqual(appData.verification_status, 'unverified');
    assert.strictEqual(appData.activation_status, 'inactive');
    appAId = appData.id;

    // Verify verification challenge was generated
    assert.ok(regRes.body.verificationChallenge);
    assert.strictEqual(regRes.body.verificationChallenge.recordName, '_deception-challenge.portal.acme.com');
    assert.strictEqual(regRes.body.verificationChallenge.recordType, 'TXT');
    assert.ok(regRes.body.verificationChallenge.token.startsWith('deception-verify-'));
    assert.strictEqual(regRes.body.verificationChallenge.status, 'pending');

    // Cross-tenant origin collision test: User registers second org, tries to use same origin
    const orgBRes = await request(app)
      .post('/api/orgs')
      .set('Authorization', `Bearer ${userBToken}`)
      .send({ name: 'Beta Industries', slug: 'beta-ind' });
    const orgBId = orgBRes.body.organisation.id;

    const dupOriginRes = await request(app)
      .post(`/api/orgs/${orgBId}/apps`)
      .set('Authorization', `Bearer ${userBToken}`)
      .send({
        displayName: 'Collision App',
        approvedDomain: 'portal.beta.com',
        configuredOrigin: 'https://app-origin.acme.internal:8443',
      });
    assert.strictEqual(dupOriginRes.status, 400);
    assert.ok(dupOriginRes.body.message.includes('already registered'));
  });

  // 6. Security Analyst RBAC restrictions
  it('6. RBAC Enforcement: Security analyst cannot create, verify, or activate applications', async () => {
    // Analyst tries to register app
    const regRes = await request(app)
      .post(`/api/orgs/${orgAId}/apps`)
      .set('Authorization', `Bearer ${userBToken}`)
      .send({
        displayName: 'Analyst App',
        approvedDomain: 'analyst.acme.com',
        configuredOrigin: 'https://analyst-origin.acme.internal',
      });
    assert.strictEqual(regRes.status, 403);

    // Analyst tries to verify app
    const verifyRes = await request(app)
      .post(`/api/orgs/${orgAId}/apps/${appAId}/verify`)
      .set('Authorization', `Bearer ${userBToken}`);
    assert.strictEqual(verifyRes.status, 403);

    // Analyst tries to activate app
    const actRes = await request(app)
      .post(`/api/orgs/${orgAId}/apps/${appAId}/activate`)
      .set('Authorization', `Bearer ${userBToken}`);
    assert.strictEqual(actRes.status, 403);

    // Analyst tries to update protection
    const protRes = await request(app)
      .put(`/api/orgs/${orgAId}/apps/${appAId}/protection`)
      .set('Authorization', `Bearer ${userBToken}`)
      .send({ diversionMode: 'ALL_SUSPICIOUS' });
    assert.strictEqual(protRes.status, 403);

    // But analyst CAN view apps and app details
    const getRes = await request(app)
      .get(`/api/orgs/${orgAId}/apps/${appAId}`)
      .set('Authorization', `Bearer ${userBToken}`);
    assert.strictEqual(getRes.status, 200);
    assert.strictEqual(getRes.body.application.id, appAId);
  });

  // 7. Security Admin permissions
  it('7. RBAC Enforcement: Security admin can manage apps but cannot delete organisation', async () => {
    // Security admin views app
    const getRes = await request(app)
      .get(`/api/orgs/${orgAId}/apps/${appAId}`)
      .set('Authorization', `Bearer ${userCToken}`);
    assert.strictEqual(getRes.status, 200);

    // Security admin tries to delete the organisation
    const delRes = await request(app)
      .delete(`/api/orgs/${orgAId}`)
      .set('Authorization', `Bearer ${userCToken}`);
    assert.strictEqual(delRes.status, 403);
  });

  // 8. Activation Guard Invariant: Unverified application cannot be activated
  it('8. Activation Guard: Unverified application cannot be activated', async () => {
    const actRes = await request(app)
      .post(`/api/orgs/${orgAId}/apps/${appAId}/activate`)
      .set('Authorization', `Bearer ${userAToken}`);

    assert.strictEqual(actRes.status, 400);
    assert.ok(actRes.body.message.includes('not verified'));

    // Verify application remains inactive
    const checkRes = await request(app)
      .get(`/api/orgs/${orgAId}/apps/${appAId}`)
      .set('Authorization', `Bearer ${userAToken}`);
    assert.strictEqual(checkRes.body.application.activation_status, 'inactive');
    assert.strictEqual(checkRes.body.application.verification_status, 'unverified');
  });

  // 9. Client Tamper Prevention: Clients cannot override verification status or active flag
  it('9. Client Tamper Prevention: Client cannot directly set verification_status or is_active via PATCH', async () => {
    const patchRes = await request(app)
      .patch(`/api/orgs/${orgAId}/apps/${appAId}`)
      .set('Authorization', `Bearer ${userAToken}`)
      .send({
        verification_status: 'verified',
        activation_status: 'active',
        is_active: true,
        displayName: 'Acme Renamed Portal',
      });

    assert.strictEqual(patchRes.status, 200);
    assert.strictEqual(patchRes.body.application.display_name, 'Acme Renamed Portal');
    // Security check: Must NOT have accepted verification_status or activation_status
    assert.strictEqual(patchRes.body.application.verification_status, 'unverified');
    assert.strictEqual(patchRes.body.application.activation_status, 'inactive');
  });

  // 10. DNS TXT Verification: Missing or Invalid TXT fails
  it('10. DNS Verification: Missing or Mismatched DNS TXT fails domain verification', async () => {
    // 1. Simulate DNS failure / empty record
    setMockDnsResolver(async (_host) => {
      throw new Error('ENOTFOUND');
    });

    const verifyFailRes = await request(app)
      .post(`/api/orgs/${orgAId}/apps/${appAId}/verify`)
      .set('Authorization', `Bearer ${userAToken}`);

    assert.strictEqual(verifyFailRes.status, 200);
    assert.strictEqual(verifyFailRes.body.verified, false);
    assert.strictEqual(verifyFailRes.body.application.verification_status, 'unverified');

    // 2. Simulate Mismatched TXT record
    setMockDnsResolver(async (_host) => {
      return [['deception-verify-wrong-token-abc123']];
    });

    const verifyMismatchRes = await request(app)
      .post(`/api/orgs/${orgAId}/apps/${appAId}/verify`)
      .set('Authorization', `Bearer ${userAToken}`);

    assert.strictEqual(verifyMismatchRes.status, 200);
    assert.strictEqual(verifyMismatchRes.body.verified, false);
    assert.strictEqual(verifyMismatchRes.body.application.verification_status, 'unverified');
  });

  // 11. DNS TXT Verification: Matching TXT marks application verified
  it('11. DNS Verification: Matching DNS TXT verifies domain ownership and allows activation', async () => {
    // Fetch latest challenge token
    const chalRes = await request(app)
      .get(`/api/orgs/${orgAId}/apps/${appAId}/verification-challenges/latest`)
      .set('Authorization', `Bearer ${userAToken}`);

    assert.strictEqual(chalRes.status, 200);
    const validToken = chalRes.body.challenge.token;
    const recordName = chalRes.body.challenge.record_name;

    // Mock DNS resolver with the correct token
    setMockDnsResolver(async (host) => {
      if (host === recordName) {
        return [[validToken]];
      }
      return [];
    });

    // Execute verification
    const verifySuccessRes = await request(app)
      .post(`/api/orgs/${orgAId}/apps/${appAId}/verify`)
      .set('Authorization', `Bearer ${userAToken}`);

    assert.strictEqual(verifySuccessRes.status, 200);
    assert.strictEqual(verifySuccessRes.body.verified, true);
    assert.strictEqual(verifySuccessRes.body.application.verification_status, 'verified');

    // Now activation MUST succeed
    const activateRes = await request(app)
      .post(`/api/orgs/${orgAId}/apps/${appAId}/activate`)
      .set('Authorization', `Bearer ${userAToken}`);

    assert.strictEqual(activateRes.status, 200);
    assert.strictEqual(activateRes.body.application.activation_status, 'active');

    // And disabling works
    const disableRes = await request(app)
      .post(`/api/orgs/${orgAId}/apps/${appAId}/disable`)
      .set('Authorization', `Bearer ${userAToken}`);

    assert.strictEqual(disableRes.status, 200);
    assert.strictEqual(disableRes.body.application.activation_status, 'disabled');
  });

  // 12. Application Protection Configuration
  it('12. Protection Configuration: Configures and persists diversion and sensitivity settings', async () => {
    const updateProtRes = await request(app)
      .put(`/api/orgs/${orgAId}/apps/${appAId}/protection`)
      .set('Authorization', `Bearer ${userAToken}`)
      .send({
        diversionMode: 'DYNAMIC',
        deceptionSensitivity: 0.85,
        allowedPaths: ['/api/public', '/login'],
        excludedPaths: ['/health', '/metrics'],
        rateLimitRpm: 120,
      });

    assert.strictEqual(updateProtRes.status, 200);
    assert.strictEqual(updateProtRes.body.protection.diversion_mode, 'DYNAMIC');
    assert.strictEqual(updateProtRes.body.protection.deception_sensitivity, 0.85);
    assert.deepStrictEqual(updateProtRes.body.protection.allowed_paths, ['/api/public', '/login']);
    assert.deepStrictEqual(updateProtRes.body.protection.excluded_paths, ['/health', '/metrics']);
    assert.strictEqual(updateProtRes.body.protection.rate_limit_rpm, 120);

    // Retrieve protection config
    const getProtRes = await request(app)
      .get(`/api/orgs/${orgAId}/apps/${appAId}/protection`)
      .set('Authorization', `Bearer ${userAToken}`);

    assert.strictEqual(getProtRes.status, 200);
    assert.strictEqual(getProtRes.body.protection.deception_sensitivity, 0.85);

    // Reject invalid sensitivity (> 1.0 or < 0)
    const badSensRes = await request(app)
      .put(`/api/orgs/${orgAId}/apps/${appAId}/protection`)
      .set('Authorization', `Bearer ${userAToken}`)
      .send({ deceptionSensitivity: 1.5 });
    assert.strictEqual(badSensRes.status, 400);
  });

  // 13. Organisation-Scoped Audit Trail
  it('13. Audit Trail: Logs organisation events with actor attribution and no credential leaks', async () => {
    const auditRes = await request(app)
      .get(`/api/orgs/${orgAId}/audit`)
      .set('Authorization', `Bearer ${userAToken}`);

    assert.strictEqual(auditRes.status, 200);
    const events = auditRes.body.auditEvents;
    assert.ok(events.length > 0);

    // Verify actor attribution and action logging
    const actionTypes = events.map((e: any) => e.action);
    assert.ok(actionTypes.includes('APPLICATION_REGISTERED'));
    assert.ok(actionTypes.includes('DOMAIN_VERIFIED'));
    assert.ok(actionTypes.includes('APPLICATION_ACTIVATED'));

    // Check every event for credential leaks
    for (const event of events) {
      assert.strictEqual(event.organisation_id, orgAId);
      const strPayload = JSON.stringify(event);
      assert.strictEqual(strPayload.includes('UserAPassword123!'), false);
      assert.strictEqual(strPayload.includes('SuperSecret'), false);
      assert.strictEqual(strPayload.includes('password_hash'), false);
    }
  });

  // 14. Membership Deletion
  it('14. Member Removal: Org owner can remove member, revoking their tenant access', async () => {
    // Remove User B from Org A
    const delRes = await request(app)
      .delete(`/api/orgs/${orgAId}/members/${userBId}`)
      .set('Authorization', `Bearer ${userAToken}`);
    assert.strictEqual(delRes.status, 200);

    // Now User B cannot view apps in Org A anymore
    const accessRes = await request(app)
      .get(`/api/orgs/${orgAId}/apps`)
      .set('Authorization', `Bearer ${userBToken}`);
    assert.strictEqual(accessRes.status, 404);
  });
});
