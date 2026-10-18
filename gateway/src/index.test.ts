import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import http from 'node:http';
import request from 'supertest';
import { createApp } from './app';
import { app as testOriginApp } from '../test-origin/src/index.js';
import { validateOriginUrl } from './config';
import { sanitizeHeaders } from './logger';
import { SessionRoutingStore } from './sessionRouter';

describe('Stage 2 & Stage 3: Gateway Reverse-Proxy & Detection Integration', () => {
  let originServer: http.Server;
  let originPort: number;
  let originUrl: string;

  let detectionServer: http.Server;
  let detectionPort: number;
  let detectionUrl: string;
  let lastReceivedFeatures: any = null;

  let gatewayApp: any;

  before(async () => {
    // 1. In-memory test-origin server
    await new Promise<void>((resolve) => {
      originServer = testOriginApp.listen(0, '127.0.0.1', () => {
        const address = originServer.address() as any;
        originPort = address.port;
        originUrl = `http://127.0.0.1:${originPort}`;
        resolve();
      });
    });

    // 2. In-memory mock detection server
    await new Promise<void>((resolve) => {
      detectionServer = http.createServer((req, res) => {
        if (req.method === 'POST' && req.url === '/score') {
          let body = '';
          req.on('data', (chunk) => {
            body += chunk;
          });
          req.on('end', () => {
            try {
              lastReceivedFeatures = JSON.parse(body);
              const score = lastReceivedFeatures.has_suspicious_keywords ? 0.85 : 0.05;
              const classification = score >= 0.70 ? 'MALICIOUS' : 'BENIGN';
              res.writeHead(200, { 'Content-Type': 'application/json' });
              res.end(
                JSON.stringify({
                  request_id: lastReceivedFeatures.request_id,
                  risk_score: score,
                  classification,
                  confidence: 0.95,
                  evidence: ['Evaluated by detection mock'],
                  inference_duration_ms: 1.5,
                })
              );
            } catch (e) {
              res.writeHead(400, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ error: 'Invalid JSON' }));
            }
          });
        } else {
          res.writeHead(404);
          res.end();
        }
      });

      detectionServer.listen(0, '127.0.0.1', () => {
        const addr = detectionServer.address() as any;
        detectionPort = addr.port;
        detectionUrl = `http://127.0.0.1:${detectionPort}`;
        resolve();
      });
    });

    // 3. Create gateway pointing to authorized test origin and detection service
    gatewayApp = createApp({
      originUrl,
      allowedOrigins: [originUrl, 'http://test-origin:5000', 'http://localhost:5000'],
      proxyTimeoutMs: 1000,
      maxRequestBodySize: 1024, // 1KB for testing limit
      detectionServiceUrl: detectionUrl,
      detectionTimeoutMs: 800,
      detectionEnabled: true,
    });
  });

  after(async () => {
    await new Promise<void>((resolve) => originServer.close(() => resolve()));
    await new Promise<void>((resolve) => detectionServer.close(() => resolve()));
  });

  describe('1. Health Check & Local Routes', () => {
    it('GET /health returns HTTP 200 with valid gateway JSON metadata and detection config', async () => {
      const res = await request(gatewayApp).get('/health');
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.headers['content-type'].includes('application/json'), true);
      assert.strictEqual(res.body.status, 'healthy');
      assert.strictEqual(res.body.service, 'gateway');
      assert.strictEqual(res.body.upstream, originUrl);
      assert.strictEqual(res.body.detectionService, detectionUrl);
      assert.strictEqual(res.body.detectionEnabled, true);
      assert.ok(typeof res.body.uptime === 'number');
      assert.ok(res.headers['x-request-id']);
    });
  });

  describe('2. Forwarding to Authorized Test Origin', () => {
    it('GET / reaches test origin and returns its identifiable response', async () => {
      const res = await request(gatewayApp).get('/');
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.headers['x-origin-id'], 'authorized-test-origin');
      assert.strictEqual(res.body.origin, 'test-origin');
      assert.strictEqual(res.body.service, 'authorized-test-origin');
      assert.strictEqual(res.body.message, 'Response from authorized test origin');
      assert.ok(res.headers['x-request-id']);
    });

    it('GET /api/echo with query parameters preserves and forwards them', async () => {
      const res = await request(gatewayApp).get('/api/echo?filter=security&page=2');
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.body.origin, 'test-origin');
      assert.strictEqual(res.body.query.filter, 'security');
      assert.strictEqual(res.body.query.page, '2');
      assert.ok(res.body.headers['x-request-id']);
    });

    it('POST /api/echo with JSON body forwards payload and preserves Set-Cookie and custom headers', async () => {
      const payload = { action: 'probe_check', target: 'gateway', sampleId: 42 };
      const res = await request(gatewayApp)
        .post('/api/echo')
        .send(payload)
        .set('Content-Type', 'application/json');

      assert.strictEqual(res.status, 201);
      assert.strictEqual(res.body.origin, 'test-origin');
      assert.deepStrictEqual(res.body.received, payload);
      assert.strictEqual(res.headers['x-origin-custom-header'], 'stage2-verified');

      // Verify Set-Cookie preservation
      const cookies = res.headers['set-cookie'];
      assert.ok(cookies);
      const cookieStr = Array.isArray(cookies) ? cookies.join('; ') : cookies;
      assert.ok(cookieStr.includes('origin_session=stage2_test_cookie_123'));
    });

    it('Forwards origin non-200 responses faithfully (400, 403, 500)', async () => {
      const res400 = await request(gatewayApp).get('/api/status/400');
      assert.strictEqual(res400.status, 400);
      assert.strictEqual(res400.body.code, 400);

      const res403 = await request(gatewayApp).get('/api/status/403');
      assert.strictEqual(res403.status, 403);
      assert.strictEqual(res403.body.code, 403);

      const res500 = await request(gatewayApp).get('/api/status/500');
      assert.strictEqual(res500.status, 500);
      assert.strictEqual(res500.body.code, 500);
    });
  });

  describe('3. Stage 3: ML Detection Integration & Shadow Mode', () => {
    it('Gateway sends derived features to detection service without sensitive headers or bodies', async () => {
      lastReceivedFeatures = null;
      const secretBody = { sensitiveData: 'confidential_password_123' };

      const res = await request(gatewayApp)
        .post('/api/echo')
        .set('Authorization', 'Bearer super_secret_token')
        .set('Cookie', 'session=secret_cookie_val')
        .send(secretBody);

      assert.strictEqual(res.status, 201);
      assert.ok(lastReceivedFeatures, 'Detection engine must receive features');

      // Verify derived features are present
      assert.ok(lastReceivedFeatures.request_id);
      assert.strictEqual(lastReceivedFeatures.method, 'POST');
      assert.strictEqual(lastReceivedFeatures.path, '/api/echo');
      assert.ok(typeof lastReceivedFeatures.path_entropy === 'number');
      assert.ok(typeof lastReceivedFeatures.body_size === 'number');

      // PRIVACY VERIFICATION: Sensitive credentials and raw bodies MUST NOT be sent
      assert.strictEqual(lastReceivedFeatures['Authorization'], undefined);
      assert.strictEqual(lastReceivedFeatures['authorization'], undefined);
      assert.strictEqual(lastReceivedFeatures['Cookie'], undefined);
      assert.strictEqual(lastReceivedFeatures['cookie'], undefined);
      assert.strictEqual(lastReceivedFeatures['body'], undefined);
      assert.strictEqual(lastReceivedFeatures['sensitiveData'], undefined);
    });

    it('Shadow Mode: Gateway forwards request to origin even when classified as MALICIOUS', async () => {
      // Path containing 'admin' triggers mock detection score = 0.85 (MALICIOUS)
      const res = await request(gatewayApp).get('/api/admin/probe');
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.headers['x-origin-id'], 'authorized-test-origin');

      // Detection headers reflect classification, but traffic was NOT blocked
      assert.strictEqual(res.headers['x-detection-classification'], 'MALICIOUS');
      assert.strictEqual(res.headers['x-detection-score'], '0.8500');
    });

    it('Fail-Open: Gateway continues forwarding normally when detection service is unavailable', async () => {
      // Gateway pointing to an offline detector port (9999)
      const deadDetectorGateway = createApp({
        originUrl,
        allowedOrigins: [originUrl],
        proxyTimeoutMs: 1000,
        maxRequestBodySize: 1024,
        detectionServiceUrl: 'http://127.0.0.1:9999',
        detectionTimeoutMs: 200,
        detectionEnabled: true,
      });

      const res = await request(deadDetectorGateway).get('/');
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.body.origin, 'test-origin');
      assert.strictEqual(res.headers['x-detection-classification'], 'UNAVAILABLE');
      assert.ok(res.headers['x-detection-error']);
    });

    it('Spoofing Protection: Client cannot manipulate or supply detection headers', async () => {
      const res = await request(gatewayApp)
        .get('/api/admin/probe')
        .set('X-Detection-Score', '0.0000')
        .set('X-Detection-Classification', 'BENIGN');

      // The gateway MUST strip spoofed client headers and compute real detection output
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.headers['x-detection-classification'], 'MALICIOUS');
      assert.strictEqual(res.headers['x-detection-score'], '0.8500');
    });
  });

  describe('4. Negative Security & Error Handling Tests', () => {
    it('Rejects requests exceeding MAX_REQUEST_BODY_SIZE with 413 Payload Too Large', async () => {
      const oversizedPayload = 'X'.repeat(2048); // limit is 1024 bytes
      const res = await request(gatewayApp)
        .post('/api/echo')
        .send({ data: oversizedPayload });

      assert.strictEqual(res.status, 413);
      assert.strictEqual(res.body.error, 'Payload Too Large');
      assert.ok(res.body.requestId);
    });

    it('Returns controlled 502 Bad Gateway when upstream origin is unavailable', async () => {
      const deadPortGateway = createApp({
        originUrl: 'http://127.0.0.1:49999',
        allowedOrigins: ['http://127.0.0.1:49999'],
        proxyTimeoutMs: 1000,
        maxRequestBodySize: 1024,
      });

      const res = await request(deadPortGateway).get('/api/anything');
      assert.strictEqual(res.status, 502);
      assert.strictEqual(res.body.error, 'Bad Gateway');
      assert.strictEqual(res.body.message, 'Upstream origin service is unavailable.');
      assert.ok(res.body.requestId);
    });

    it('Returns controlled 504 Gateway Timeout when upstream origin exceeds proxyTimeoutMs', async () => {
      const timeoutGateway = createApp({
        originUrl,
        allowedOrigins: [originUrl],
        proxyTimeoutMs: 400,
        maxRequestBodySize: 1024,
      });

      const res = await request(timeoutGateway).get('/api/delay/1500');
      assert.strictEqual(res.status, 504);
      assert.strictEqual(res.body.error, 'Gateway Timeout');
      assert.strictEqual(res.body.message, 'Upstream origin service timed out.');
      assert.ok(res.body.requestId);
    });

    it('Prevents open-proxy & SSRF: Client Host or X-Forwarded-Host cannot alter upstream', async () => {
      const res = await request(gatewayApp)
        .get('/api/echo')
        .set('Host', '169.254.169.254')
        .set('X-Forwarded-Host', 'malicious-attacker.com')
        .set('X-Proxy-Target', 'http://internal-secret-service');

      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.headers['x-origin-id'], 'authorized-test-origin');
      assert.strictEqual(res.body.origin, 'test-origin');
    });

    it('Rejects suspicious path traversal attempts with 400 Bad Request', async () => {
      const res = await request(gatewayApp).get('/../etc/passwd');
      assert.strictEqual(res.status, 400);
      assert.strictEqual(res.body.error, 'Bad Request');
    });

    it('Validates origin whitelist and rejects unapproved origins at configuration time', () => {
      const allowed = ['http://test-origin:5000', 'http://localhost:5000'];
      const valid = validateOriginUrl('http://test-origin:5000', allowed);
      assert.strictEqual(valid.origin, 'http://test-origin:5000');

      assert.throws(
        () => validateOriginUrl('http://169.254.169.254/latest/meta-data', allowed),
        /Forbidden ORIGIN_URL/
      );
    });

    it('Redacts sensitive headers from logging metadata', () => {
      const rawHeaders = {
        'content-type': 'application/json',
        authorization: 'Bearer super_secret_token_123',
        cookie: 'session=secret_cookie_val',
        'set-cookie': 'session=new_secret_cookie_val',
        'x-api-key': 'api-key-9999',
        'user-agent': 'SafeUserAgent',
      };

      const sanitized = sanitizeHeaders(rawHeaders);
      assert.strictEqual(sanitized['content-type'], 'application/json');
      assert.strictEqual(sanitized['user-agent'], 'SafeUserAgent');
      assert.strictEqual(sanitized['authorization'], '[REDACTED]');
      assert.strictEqual(sanitized['cookie'], '[REDACTED]');
      assert.strictEqual(sanitized['set-cookie'], '[REDACTED]');
      assert.strictEqual(sanitized['x-api-key'], '[REDACTED]');
    });
  });

  describe('5. Stage 5: Policy-Controlled Traffic Diversion & Decision Controller', () => {
    let deceptionServer: http.Server;
    let deceptionPort: number;
    let deceptionUrl: string;

    let activeGatewayApp: any;
    let shadowGatewayApp: any;
    let fallbackGatewayApp: any;
    let customSessionStore: SessionRoutingStore;

    before(async () => {
      // Import and start in-memory deception runtime
      const { createApp: createDeceptionApp } = await import('../../deception/src/app');
      await new Promise<void>((resolve) => {
        deceptionServer = createDeceptionApp().listen(0, '127.0.0.1', () => {
          const addr = deceptionServer.address() as any;
          deceptionPort = addr.port;
          deceptionUrl = `http://127.0.0.1:${deceptionPort}`;
          resolve();
        });
      });

      customSessionStore = new SessionRoutingStore(1800000, 100);

      activeGatewayApp = createApp(
        {
          originUrl,
          deceptionServiceUrl: deceptionUrl,
          allowedOrigins: [originUrl, deceptionUrl, 'http://test-origin:5000', 'http://deception:5050'],
          proxyTimeoutMs: 1500,
          maxRequestBodySize: 1048576,
          detectionServiceUrl: detectionUrl,
          detectionTimeoutMs: 800,
          detectionEnabled: true,
          routingMode: 'active',
          emergencyDisableDiversion: false,
          deceptionScoreThreshold: 0.70,
        },
        customSessionStore
      );

      shadowGatewayApp = createApp({
        originUrl,
        deceptionServiceUrl: deceptionUrl,
        allowedOrigins: [originUrl, deceptionUrl],
        proxyTimeoutMs: 1500,
        maxRequestBodySize: 1048576,
        detectionServiceUrl: detectionUrl,
        detectionTimeoutMs: 800,
        detectionEnabled: true,
        routingMode: 'shadow',
        emergencyDisableDiversion: false,
        deceptionScoreThreshold: 0.70,
      });

      fallbackGatewayApp = createApp({
        originUrl,
        deceptionServiceUrl: 'http://127.0.0.1:49997', // Offline deception port
        allowedOrigins: [originUrl, 'http://127.0.0.1:49997'],
        proxyTimeoutMs: 1500,
        maxRequestBodySize: 1048576,
        detectionServiceUrl: detectionUrl,
        detectionTimeoutMs: 800,
        detectionEnabled: true,
        routingMode: 'active',
        emergencyDisableDiversion: false,
        deceptionScoreThreshold: 0.70,
      });
    });

    after(async () => {
      if (deceptionServer) {
        await new Promise<void>((resolve) => deceptionServer.close(() => resolve()));
      }
    });

    it('Health check exposes Stage 5 routing metadata, mode, and active deception counts', async () => {
      const res = await request(activeGatewayApp).get('/health');
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.body.stage, 'Stage 5 — Policy-Controlled Traffic Diversion');
      assert.strictEqual(res.body.routingMode, 'active');
      assert.strictEqual(res.body.emergencyDisableDiversion, false);
      assert.strictEqual(res.body.deceptionService, deceptionUrl);
      assert.strictEqual(res.body.deceptionThreshold, 0.70);
      assert.strictEqual(typeof res.body.activeDeceptionSessions, 'number');
    });

    it('Shadow Mode Invariant: High-confidence malicious request never diverts to deception', async () => {
      const res = await request(shadowGatewayApp).get('/api/admin/probe');
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.headers['x-routing-decision'], 'ORIGIN');
      assert.strictEqual(res.headers['x-routing-reason'], 'SHADOW_MODE_ACTIVE');
      assert.strictEqual(res.headers['x-routing-mode'], 'shadow');
      assert.strictEqual(res.headers['x-origin-id'], 'authorized-test-origin');
      assert.strictEqual(res.headers['x-deception-runtime'], undefined);
    });

    it('Active Mode: Benign request routes to legitimate test origin', async () => {
      const res = await request(activeGatewayApp).get('/api/echo');
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.headers['x-routing-decision'], 'ORIGIN');
      assert.strictEqual(res.headers['x-routing-reason'], 'BENIGN_EVALUATION');
      assert.strictEqual(res.headers['x-routing-mode'], 'active');
      assert.strictEqual(res.body.origin, 'test-origin');
    });

    it('Active Mode: High-confidence malicious request diverts to isolated deception runtime', async () => {
      const attackerSessionId = 'session-attacker-alpha-1';
      const res = await request(activeGatewayApp)
        .get('/api/admin')
        .set('X-Session-ID', attackerSessionId);

      assert.strictEqual(res.headers['x-routing-decision'], 'DECEPTION');
      assert.strictEqual(res.headers['x-routing-reason'], 'HIGH_CONFIDENCE_MALICIOUS_DIVERT');
      assert.strictEqual(res.headers['x-routing-mode'], 'active');
      assert.strictEqual(res.headers['x-deception-runtime'], 'active');
      assert.strictEqual(res.headers['x-session-id'], attackerSessionId);
      assert.ok(customSessionStore.isSessionAssignedToDeception(attackerSessionId));
    });

    it('Session Continuity: Subsequent requests from diverted session remain sticky in deception runtime', async () => {
      const stickySessionId = 'session-attacker-alpha-1';
      // Now requesting /api/catalog which exists in deception runtime
      const res = await request(activeGatewayApp)
        .get('/api/catalog')
        .set('X-Session-ID', stickySessionId);

      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.headers['x-routing-decision'], 'DECEPTION');
      assert.strictEqual(res.headers['x-routing-reason'], 'STICKY_SESSION_ASSIGNMENT');
      assert.strictEqual(res.headers['x-deception-runtime'], 'active');
      assert.strictEqual(res.headers['x-dsg-current-node'], 'catalog');
      assert.strictEqual(res.body.service, 'catalog');
    });

    it('Emergency Killswitch: Halts all diversion immediately and forces traffic to origin', async () => {
      // 1. Activate emergency disable
      const disableRes = await request(activeGatewayApp).post('/api/gateway/emergency-disable');
      assert.strictEqual(disableRes.status, 200);
      assert.strictEqual(disableRes.body.status, 'emergency_disable_activated');

      // 2. High-confidence malicious request should now route to ORIGIN
      const res = await request(activeGatewayApp)
        .get('/api/admin/probe')
        .set('X-Session-ID', 'session-attacker-emergency');

      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.headers['x-routing-decision'], 'ORIGIN');
      assert.strictEqual(res.headers['x-routing-reason'], 'EMERGENCY_DISABLE_ACTIVE');
      assert.strictEqual(res.headers['x-origin-id'], 'authorized-test-origin');

      // 3. Reactivate diversion
      const enableRes = await request(activeGatewayApp).post('/api/gateway/emergency-enable');
      assert.strictEqual(enableRes.status, 200);
      assert.strictEqual(enableRes.body.status, 'emergency_disable_deactivated');
    });

    it('Session Reset: Clears session stickiness upon operator reset', async () => {
      const resetSessionId = 'session-to-reset-99';
      customSessionStore.assignSessionToDeception(resetSessionId, 'MANUAL_TEST', 0.88);
      assert.strictEqual(customSessionStore.isSessionAssignedToDeception(resetSessionId), true);

      const resetRes = await request(activeGatewayApp)
        .post('/api/gateway/sessions/reset')
        .send({ sessionId: resetSessionId });

      assert.strictEqual(resetRes.status, 200);
      assert.strictEqual(resetRes.body.status, 'session_cleared');
      assert.strictEqual(customSessionStore.isSessionAssignedToDeception(resetSessionId), false);
    });

    it('Safe Fallback: Deception runtime failure automatically falls back to origin without error', async () => {
      const res = await request(fallbackGatewayApp)
        .get('/api/admin/probe')
        .set('X-Session-ID', 'session-fallback-test');

      // Gateway catches unreachable deception runtime and forwards safely to origin
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.headers['x-routing-fallback'], 'deception-unavailable');
      assert.strictEqual(res.headers['x-routing-decision'], 'ORIGIN');
      assert.strictEqual(res.headers['x-origin-id'], 'authorized-test-origin');
    });

    it('Safe Fallback: Detection service unavailable falls back to origin in active mode', async () => {
      const deadDetectorActiveApp = createApp({
        originUrl,
        deceptionServiceUrl: deceptionUrl,
        allowedOrigins: [originUrl, deceptionUrl],
        proxyTimeoutMs: 1500,
        maxRequestBodySize: 1048576,
        detectionServiceUrl: 'http://127.0.0.1:9999',
        detectionTimeoutMs: 100,
        detectionEnabled: true,
        routingMode: 'active',
        deceptionScoreThreshold: 0.70,
      });

      const res = await request(deadDetectorActiveApp).get('/');
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.headers['x-routing-decision'], 'ORIGIN');
      assert.strictEqual(res.headers['x-routing-reason'], 'DETECTION_UNAVAILABLE_FALLBACK');
      assert.strictEqual(res.body.origin, 'test-origin');
    });

    it('Client Spoofing Prevention: Strips client routing headers and enforces server policy', async () => {
      const res = await request(activeGatewayApp)
        .get('/api/echo')
        .set('X-Routing-Decision', 'DECEPTION')
        .set('X-Routing-Mode', 'shadow')
        .set('X-Routing-Fallback', 'none');

      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.headers['x-routing-decision'], 'ORIGIN');
      assert.strictEqual(res.headers['x-routing-mode'], 'active');
      assert.strictEqual(res.headers['x-routing-fallback'], undefined);
    });

    it('Pseudonymous Session Derivation: Securely hashes client features if no header provided', async () => {
      const res = await request(activeGatewayApp).get('/api/echo');
      assert.strictEqual(res.status, 200);
      const returnedSessionId = res.headers['x-session-id'];
      assert.ok(returnedSessionId);
      assert.ok(returnedSessionId.startsWith('sess_'));
      assert.strictEqual(returnedSessionId.length >= 10, true);
    });

    it('Decision Controller Unit Tests: Strict evaluation and boundary checks', async () => {
      const { evaluateRoutingPolicy } = await import('./controller');

      // Emergency disable takes absolute priority
      const emergencyResult = evaluateRoutingPolicy({
        riskScore: 0.99,
        classification: 'MALICIOUS',
        evidence: ['high_risk'],
        sessionId: 'sess_1',
        hasExistingDeceptionAssignment: true,
        routingMode: 'active',
        emergencyDisableDiversion: true,
        deceptionScoreThreshold: 0.70,
      });
      assert.strictEqual(emergencyResult.target, 'ORIGIN');
      assert.strictEqual(emergencyResult.reason, 'EMERGENCY_DISABLE_ACTIVE');

      // Shadow mode invariant
      const shadowResult = evaluateRoutingPolicy({
        riskScore: 0.95,
        classification: 'MALICIOUS',
        evidence: ['critical_attack'],
        sessionId: 'sess_2',
        hasExistingDeceptionAssignment: false,
        routingMode: 'shadow',
        emergencyDisableDiversion: false,
        deceptionScoreThreshold: 0.70,
      });
      assert.strictEqual(shadowResult.target, 'ORIGIN');
      assert.strictEqual(shadowResult.reason, 'SHADOW_MODE_ACTIVE');

      // Malformed / NaN score fallback
      const nanResult = evaluateRoutingPolicy({
        riskScore: NaN,
        classification: 'MALICIOUS',
        evidence: [],
        sessionId: 'sess_3',
        hasExistingDeceptionAssignment: false,
        routingMode: 'active',
        emergencyDisableDiversion: false,
        deceptionScoreThreshold: 0.70,
      });
      assert.strictEqual(nanResult.target, 'ORIGIN');
      assert.strictEqual(nanResult.reason, 'DETECTION_UNAVAILABLE_FALLBACK');

      // Suspicious below threshold -> OBSERVE_ONLY
      const suspiciousResult = evaluateRoutingPolicy({
        riskScore: 0.55,
        classification: 'SUSPICIOUS',
        evidence: ['recon'],
        sessionId: 'sess_4',
        hasExistingDeceptionAssignment: false,
        routingMode: 'active',
        emergencyDisableDiversion: false,
        deceptionScoreThreshold: 0.70,
      });
      assert.strictEqual(suspiciousResult.target, 'OBSERVE_ONLY');
      assert.strictEqual(suspiciousResult.reason, 'SUSPICIOUS_OBSERVE_ONLY');

      // High confidence multi-factor malicious -> DECEPTION
      const maliciousResult = evaluateRoutingPolicy({
        riskScore: 0.85,
        classification: 'MALICIOUS',
        evidence: ['admin_probe', 'sqli_detected'],
        sessionId: 'sess_5',
        hasExistingDeceptionAssignment: false,
        routingMode: 'active',
        emergencyDisableDiversion: false,
        deceptionScoreThreshold: 0.70,
      });
      assert.strictEqual(maliciousResult.target, 'DECEPTION');
      assert.strictEqual(maliciousResult.reason, 'HIGH_CONFIDENCE_MALICIOUS_DIVERT');
    });

    it('SessionRoutingStore Unit Tests: Sliding TTL, capacity eviction, and resets', async () => {
      const { SessionRoutingStore } = await import('./sessionRouter');
      const store = new SessionRoutingStore(50, 2); // 50ms TTL, max 2 capacity

      store.assignSessionToDeception('sess_a', 'REASON_A', 0.8);
      store.assignSessionToDeception('sess_b', 'REASON_B', 0.9);
      assert.strictEqual(store.isSessionAssignedToDeception('sess_a'), true);
      assert.strictEqual(store.isSessionAssignedToDeception('sess_b'), true);

      // LRU Eviction: Adding a 3rd session evicts oldest
      store.assignSessionToDeception('sess_c', 'REASON_C', 0.95);
      assert.strictEqual(store.getActiveDeceptionCount() <= 2, true);

      // Expiration check
      await new Promise((r) => setTimeout(r, 60));
      assert.strictEqual(store.isSessionAssignedToDeception('sess_c'), false);
    });
  });
});

