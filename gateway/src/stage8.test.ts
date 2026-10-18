import { describe, it, before, after, beforeEach } from 'node:test';
import assert from 'node:assert';
import http from 'node:http';
import request from 'supertest';
import jwt from 'jsonwebtoken';
import { createApp } from './app';
import { SessionRoutingStore } from './sessionRouter';
import { MetricsCollector } from './metrics';
import { SecurityEventRecorder } from './eventRecorder';
import { calculateDES, DEFAULT_DES_WEIGHTS } from './des';

describe('Stage 8: End-to-End Security Validation & Evaluation Framework', () => {
  let originServer: http.Server;
  let originPort: number;
  let originUrl: string;

  let detectionServer: http.Server;
  let detectionPort: number;
  let detectionUrl: string;

  let deceptionServer: http.Server;
  let deceptionPort: number;
  let deceptionUrl: string;

  let originHitCount = 0;
  let deceptionHitCount = 0;
  let detectionHitCount = 0;

  // Configurable mock states
  let detectionShouldTimeout = false;
  let detectionShouldError = false;
  let deceptionShouldTimeout = false;
  let deceptionShouldError = false;

  const JWT_SECRET = 'test-operator-jwt-secret-key-32chars!';
  const adminToken = jwt.sign(
    { sub: 'op_admin', username: 'sec_admin', role: 'admin', permissions: ['routing:control', 'sessions:reset', 'routing:read'] },
    JWT_SECRET,
    { expiresIn: '1h' }
  );
  const analystToken = jwt.sign(
    { sub: 'op_analyst', username: 'sec_analyst', role: 'analyst', permissions: ['routing:read', 'sessions:read'] },
    JWT_SECRET,
    { expiresIn: '1h' }
  );

  let sessionRouter: SessionRoutingStore;
  let metricsCollector: MetricsCollector;
  let eventRecorder: SecurityEventRecorder;
  let gatewayApp: any;

  before(async () => {
    // 1. Authorized Test Origin Server
    await new Promise<void>((resolve) => {
      originServer = http.createServer((req, res) => {
        originHitCount++;
        res.setHeader('Content-Type', 'application/json');
        res.setHeader('X-Origin-Id', 'authorized-test-origin');
        res.writeHead(200);
        res.end(
          JSON.stringify({
            origin: 'test-origin',
            path: req.url,
            method: req.method,
            originHitCount,
          })
        );
      });
      originServer.listen(0, '127.0.0.1', () => {
        const addr = originServer.address() as any;
        originPort = addr.port;
        originUrl = `http://127.0.0.1:${originPort}`;
        resolve();
      });
    });

    // 2. Mock ML Detection Service
    await new Promise<void>((resolve) => {
      detectionServer = http.createServer((req, res) => {
        detectionHitCount++;

        if (detectionShouldTimeout) {
          // Do not reply - trigger timeout
          return;
        }

        if (detectionShouldError) {
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Internal Detection Error' }));
          return;
        }

        let body = '';
        req.on('data', (c) => (body += c));
        req.on('end', () => {
          try {
            const parsed = JSON.parse(body);
            const path = parsed.path || '';

            let risk_score = 0.05;
            let classification = 'BENIGN';
            let evidence = ['Normal path evaluation'];

            if (path.includes('probe') || path.includes('admin') || path.includes('attack') || path.includes('sqli') || parsed.has_suspicious_keywords) {
              risk_score = 0.92;
              classification = 'MALICIOUS';
              evidence = ['Suspicious keyword in path', 'High anomaly score'];
            } else if (path.includes('suspicious') || path.includes('filter=suspicious')) {
              risk_score = 0.45;
              classification = 'SUSPICIOUS';
              evidence = ['Unusual query parameter'];
            }

            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(
              JSON.stringify({
                request_id: parsed.request_id,
                risk_score,
                classification,
                confidence: 0.95,
                evidence,
                inference_duration_ms: 1.2,
              })
            );
          } catch {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Bad JSON' }));
          }
        });
      });
      detectionServer.listen(0, '127.0.0.1', () => {
        const addr = detectionServer.address() as any;
        detectionPort = addr.port;
        detectionUrl = `http://127.0.0.1:${detectionPort}`;
        resolve();
      });
    });

    // 3. Isolated Deception Runtime Mock
    await new Promise<void>((resolve) => {
      deceptionServer = http.createServer((req, res) => {
        deceptionHitCount++;

        if (deceptionShouldTimeout) {
          // Do not reply - trigger gateway proxy timeout
          return;
        }

        if (deceptionShouldError) {
          req.socket?.destroy();
          return;
        }

        res.setHeader('Content-Type', 'application/json');
        res.setHeader('X-Deception-Runtime', 'active');
        res.setHeader('X-DSG-Current-Node', 'RECON_DISCOVERY');
        res.writeHead(200);
        res.end(
          JSON.stringify({
            environment: 'isolated-dynamic-deception',
            dsgNode: 'RECON_DISCOVERY',
            path: req.url,
            deceptionHitCount,
          })
        );
      });
      deceptionServer.listen(0, '127.0.0.1', () => {
        const addr = deceptionServer.address() as any;
        deceptionPort = addr.port;
        deceptionUrl = `http://127.0.0.1:${deceptionPort}`;
        resolve();
      });
    });
  });

  beforeEach(() => {
    originHitCount = 0;
    deceptionHitCount = 0;
    detectionHitCount = 0;
    detectionShouldTimeout = false;
    detectionShouldError = false;
    deceptionShouldTimeout = false;
    deceptionShouldError = false;

    sessionRouter = new SessionRoutingStore(1000, 300);
    metricsCollector = new MetricsCollector();
    eventRecorder = new SecurityEventRecorder();

    gatewayApp = createApp(
      {
        originUrl,
        allowedOrigins: [originUrl, deceptionUrl, 'http://test-origin:5000', 'http://deception:5050'],
        proxyTimeoutMs: 500,
        detectionServiceUrl: detectionUrl,
        detectionTimeoutMs: 300,
        detectionEnabled: true,
        routingMode: 'active',
        deceptionServiceUrl: deceptionUrl,
        deceptionScoreThreshold: 0.70,
        operatorJwtSecret: JWT_SECRET,
        deceptionFailurePolicy: 'quarantine',
      },
      sessionRouter,
      metricsCollector,
      eventRecorder
    );
  });

  after(async () => {
    await new Promise<void>((resolve) => originServer.close(() => resolve()));
    await new Promise<void>((resolve) => detectionServer.close(() => resolve()));
    await new Promise<void>((resolve) => deceptionServer.close(() => resolve()));
  });

  // =========================================================================
  // 1. End-to-End Request Paths & Security Event Pipeline
  // =========================================================================
  describe('1. End-to-End Request Paths & Unified Security Event Recording', () => {
    it('Benign request reaches authorized origin and records ORIGIN event', async () => {
      const res = await request(gatewayApp)
        .get('/api/catalog?category=books')
        .set('User-Agent', 'Mozilla/5.0 TestBrowser');

      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.headers['x-routing-decision'], 'ORIGIN');
      assert.strictEqual(res.headers['x-origin-id'], 'authorized-test-origin');
      assert.strictEqual(res.headers['x-deception-runtime'], undefined);
      assert.strictEqual(originHitCount, 1);
      assert.strictEqual(deceptionHitCount, 0);

      // Verify security event recording
      const events = eventRecorder.getRecentEvents(10);
      assert.strictEqual(events.length, 1);
      const evt = events[0];
      assert.strictEqual(evt.method, 'GET');
      assert.strictEqual(evt.path, '/api/catalog?category=books');
      assert.strictEqual(evt.statusCode, 200);
      assert.strictEqual(evt.routingDecision, 'ORIGIN');
      assert.strictEqual(evt.failureQuarantined, false);
      assert.ok(evt.durationMs >= 0);
      assert.ok(typeof evt.detectionScore === 'number');
    });

    it('Suspicious request remains on normal route in observe mode and records OBSERVE_ONLY event', async () => {
      const res = await request(gatewayApp)
        .get('/api/suspicious/items')
        .set('User-Agent', 'Mozilla/5.0 TestBrowser');

      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.headers['x-routing-decision'], 'OBSERVE_ONLY');
      assert.strictEqual(res.headers['x-origin-id'], 'authorized-test-origin');
      assert.strictEqual(originHitCount, 1);
      assert.strictEqual(deceptionHitCount, 0);

      const events = eventRecorder.getRecentEvents(10);
      assert.strictEqual(events.length, 1);
      assert.strictEqual(events[0].routingDecision, 'OBSERVE_ONLY');
      assert.strictEqual(events[0].statusCode, 200);
    });

    it('High-confidence attack in active mode diverts to deception runtime and records DECEPTION event', async () => {
      const res = await request(gatewayApp)
        .get('/api/admin/probe')
        .set('User-Agent', 'SqlMap/1.4.7');

      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.headers['x-routing-decision'], 'DECEPTION');
      assert.strictEqual(res.headers['x-deception-runtime'], 'active');
      assert.strictEqual(res.headers['x-origin-id'], undefined);
      assert.strictEqual(originHitCount, 0);
      assert.strictEqual(deceptionHitCount, 1);

      const events = eventRecorder.getRecentEvents(10);
      assert.strictEqual(events.length, 1);
      assert.strictEqual(events[0].routingDecision, 'DECEPTION');
      assert.strictEqual(events[0].failureQuarantined, false);
    });

    it('Sticky deception session maintains synthetic state across repeated requests', async () => {
      // 1. Initial malicious request triggers deception diversion
      const res1 = await request(gatewayApp).get('/api/admin/probe');
      const sessionId = res1.headers['x-session-id'];
      assert.ok(sessionId);
      assert.strictEqual(res1.headers['x-routing-decision'], 'DECEPTION');
      assert.strictEqual(deceptionHitCount, 1);
      assert.strictEqual(originHitCount, 0);

      // 2. Subsequent benign request with the same session cookie remains in deception
      const res2 = await request(gatewayApp)
        .get('/api/catalog')
        .set('Cookie', `deception_session=${sessionId}`);

      assert.strictEqual(res2.headers['x-routing-decision'], 'DECEPTION');
      assert.strictEqual(res2.headers['x-routing-reason'], 'STICKY_SESSION_ASSIGNMENT');
      assert.strictEqual(res2.headers['x-deception-runtime'], 'active');
      assert.strictEqual(deceptionHitCount, 2);
      assert.strictEqual(originHitCount, 0); // Origin was NEVER touched!
    });
  });

  // =========================================================================
  // 2. Fail-Safe, Quarantine Invariants & Resilience
  // =========================================================================
  describe('2. Fail-Safe Invariants, Quarantine & Recovery', () => {
    it('Detection service failure / timeout safely falls back to origin in active mode (fail-open)', async () => {
      detectionShouldTimeout = true;

      const res = await request(gatewayApp).get('/api/catalog');
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.headers['x-routing-decision'], 'ORIGIN');
      assert.strictEqual(res.headers['x-origin-id'], 'authorized-test-origin');
      assert.strictEqual(originHitCount, 1);
      assert.ok(res.headers['x-detection-error']);

      // Metrics capture the error
      const summary = metricsCollector.getSummary();
      assert.ok(summary.detection.errors >= 1);
    });

    it('Deception runtime failure strictly quarantines attacker (503 Service Unavailable, ZERO origin leakage)', async () => {
      deceptionShouldError = true;

      const res = await request(gatewayApp).get('/api/admin/probe');
      assert.strictEqual(res.status, 503);
      assert.strictEqual(res.headers['x-routing-decision'], 'DECEPTION');
      assert.strictEqual(res.headers['x-routing-fallback'], 'quarantined');
      assert.strictEqual(res.body.error, 'Service Unavailable');
      assert.strictEqual(originHitCount, 0); // Attacker NEVER exposed to real origin!

      const events = eventRecorder.getRecentEvents(10);
      assert.strictEqual(events[0].statusCode, 503);
      assert.strictEqual(events[0].failureQuarantined, true);
      assert.strictEqual(events[0].routingDecision, 'DECEPTION');

      const summary = metricsCollector.getSummary();
      assert.strictEqual(summary.quarantinedRequests, 1);
    });

    it('Emergency disable killswitch immediately bypasses deception; re-enable restores diversion', async () => {
      // 1. Activate emergency disable
      const disableRes = await request(gatewayApp)
        .post('/api/gateway/emergency-disable')
        .set('Authorization', `Bearer ${adminToken}`);
      assert.strictEqual(disableRes.status, 200);
      assert.strictEqual(disableRes.body.emergencyDisableDiversion, true);

      // 2. Attack request should now bypass deception and hit origin
      const bypassRes = await request(gatewayApp).get('/api/admin/probe');
      assert.strictEqual(bypassRes.status, 200);
      assert.strictEqual(bypassRes.headers['x-routing-decision'], 'ORIGIN');
      assert.strictEqual(bypassRes.headers['x-routing-reason'], 'EMERGENCY_DISABLE_ACTIVE');
      assert.strictEqual(originHitCount, 1);
      assert.strictEqual(deceptionHitCount, 0);

      // 3. Re-enable emergency controls
      const enableRes = await request(gatewayApp)
        .post('/api/gateway/emergency-enable')
        .set('Authorization', `Bearer ${adminToken}`);
      assert.strictEqual(enableRes.status, 200);
      assert.strictEqual(enableRes.body.emergencyDisableDiversion, false);

      // 4. Attack request now diverts to deception
      const divertRes = await request(gatewayApp).get('/api/admin/probe');
      assert.strictEqual(divertRes.headers['x-routing-decision'], 'DECEPTION');
      assert.strictEqual(deceptionHitCount, 1);
    });
  });

  // =========================================================================
  // 3. Adversarial Boundary Defenses & Tamper Resistance
  // =========================================================================
  describe('3. Adversarial Boundary Defenses & Tamper Resistance', () => {
    it('Client header spoofing: Injected routing headers are stripped and server policy enforced', async () => {
      const res = await request(gatewayApp)
        .get('/api/admin/attack')
        .set('X-Routing-Decision', 'ORIGIN')
        .set('X-Detection-Score', '0.01')
        .set('X-Detection-Classification', 'BENIGN');

      assert.strictEqual(res.headers['x-routing-decision'], 'DECEPTION');
      assert.strictEqual(deceptionHitCount, 1);
      assert.strictEqual(originHitCount, 0);
    });

    it('Session fixation defense: Malformed/traversal session tokens are rejected and renewed', async () => {
      const res = await request(gatewayApp)
        .get('/api/catalog')
        .set('X-Session-ID', '../../etc/passwd');

      assert.strictEqual(res.status, 200);
      const returnedSessionId = res.headers['x-session-id'];
      assert.notStrictEqual(returnedSessionId, '../../etc/passwd');
      assert.ok(returnedSessionId.startsWith('sess_'));
    });

    it('Credential redaction in security event pipeline protects sensitive query parameters', async () => {
      await request(gatewayApp)
        .get('/api/login?token=super_secret_token_12345&password=mySecretPassword!&user=alice');

      const events = eventRecorder.getRecentEvents(10);
      assert.strictEqual(events.length, 1);
      assert.strictEqual(events[0].path.includes('super_secret_token_12345'), false);
      assert.strictEqual(events[0].path.includes('mySecretPassword!'), false);
      assert.strictEqual(events[0].path.includes('token=%5BREDACTED%5D') || events[0].path.includes('token=[REDACTED]'), true);
    });

    it('Operator RBAC: Analyst cannot manipulate emergency controls; Admin succeeds', async () => {
      // Analyst attempt (Forbidden 403)
      const analystRes = await request(gatewayApp)
        .post('/api/gateway/emergency-disable')
        .set('Authorization', `Bearer ${analystToken}`);
      assert.strictEqual(analystRes.status, 403);

      // Admin attempt (Success 200)
      const adminRes = await request(gatewayApp)
        .post('/api/gateway/emergency-disable')
        .set('Authorization', `Bearer ${adminToken}`);
      assert.strictEqual(adminRes.status, 200);

      // Cleanup
      await request(gatewayApp)
        .post('/api/gateway/emergency-enable')
        .set('Authorization', `Bearer ${adminToken}`);
    });
  });

  // =========================================================================
  // 4. Concurrency Load Test & Race Condition Resilience
  // =========================================================================
  describe('4. Concurrency Load Test & Race Condition Resilience', () => {
    it('Processes 30 concurrent mixed requests without crosstalk or dropped requests', async () => {
      const requests = Array.from({ length: 30 }, (_, i) => {
        const isAttack = i % 2 === 0;
        const path = isAttack ? `/api/admin/probe_${i}` : `/api/catalog_${i}`;
        return request(gatewayApp)
          .get(path)
          .set('X-Session-ID', `concurrent_test_session_${i % 5}`)
          .then((res) => ({ index: i, isAttack, status: res.status, decision: res.headers['x-routing-decision'] }));
      });

      const results = await Promise.all(requests);
      assert.strictEqual(results.length, 30);

      for (const r of results) {
        assert.strictEqual(r.status, 200);
        assert.ok(r.decision === 'ORIGIN' || r.decision === 'DECEPTION');
      }

      // Check operational metrics collector
      const metrics = metricsCollector.getSummary();
      assert.strictEqual(metrics.totalRequests, 30);
      assert.ok(metrics.routingBreakdown.ORIGIN > 0);
      assert.ok(metrics.routingBreakdown.DECEPTION > 0);
      assert.ok(metrics.gatewayLatency.p50Ms >= 0);
      assert.ok(metrics.gatewayLatency.p95Ms >= 0);
    });

    it('Handles concurrent emergency disable toggle during active traffic without errors', async () => {
      const togglePromise = request(gatewayApp)
        .post('/api/gateway/emergency-disable')
        .set('Authorization', `Bearer ${adminToken}`);

      const trafficPromises = Array.from({ length: 10 }, (_, i) =>
        request(gatewayApp).get(`/api/admin/race_${i}`)
      );

      const [toggleRes, ...trafficResults] = await Promise.all([togglePromise, ...trafficPromises]);
      assert.strictEqual(toggleRes.status, 200);

      for (const r of trafficResults) {
        assert.strictEqual(r.status, 200);
      }

      // Restore
      await request(gatewayApp)
        .post('/api/gateway/emergency-enable')
        .set('Authorization', `Bearer ${adminToken}`);
    });
  });

  // =========================================================================
  // 5. Operational Observability & Metrics API
  // =========================================================================
  describe('5. Operational Observability & Metrics Endpoints', () => {
    it('GET /api/gateway/metrics exposes real-time latencies, breakdowns, and error counters', async () => {
      // Generate some test traffic
      await request(gatewayApp).get('/api/catalog');
      await request(gatewayApp).get('/api/admin/probe');

      const res = await request(gatewayApp).get('/api/gateway/metrics');
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.body.service, 'gateway');
      assert.strictEqual(res.body.totalRequests, 2);
      assert.strictEqual(res.body.routingBreakdown.ORIGIN, 1);
      assert.strictEqual(res.body.routingBreakdown.DECEPTION, 1);
      assert.ok(res.body.gatewayLatency.p50Ms >= 0);
      assert.ok(res.body.gatewayLatency.p95Ms >= 0);
      assert.ok(res.body.detection.availabilityPct > 0);
    });

    it('GET /api/gateway/events exposes recent security events with limit control', async () => {
      await request(gatewayApp).get('/api/catalog');
      await request(gatewayApp).get('/api/admin/probe');

      const res = await request(gatewayApp).get('/api/gateway/events?limit=5');
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.body.total, 2);
      assert.strictEqual(res.body.events.length, 2);
    });
  });

  // =========================================================================
  // 6. Deception Effectiveness Score (DES) Mathematical Verification
  // =========================================================================
  describe('6. Deception Effectiveness Score (DES) Formulation', () => {
    it('Calculates high DES for complete engagement with zero leakage', () => {
      const result = calculateDES({
        originLeakCount: 0,
        uniqueDsgNodesVisited: 4,
        totalAccessibleDsgNodes: 4,
        successfulDeceptionInteractions: 10,
        totalDeceptionInteractions: 10,
        uniqueDecoyEndpointsTargeted: 4,
        totalDecoyEndpoints: 4,
        dwellTargetInteractions: 10,
      });

      assert.strictEqual(result.originLeakage, false);
      assert.strictEqual(result.score, 1.0);
      assert.strictEqual(result.components.depthScore, 1.0);
      assert.strictEqual(result.components.consistencyScore, 1.0);
      assert.strictEqual(result.components.dwellScore, 1.0);
      assert.strictEqual(result.components.engagementScore, 1.0);
      assert.ok(result.limitations.length > 0);
    });

    it('Origin leakage gate: ANY leak forces DES strictly to 0.0', () => {
      const result = calculateDES({
        originLeakCount: 1, // 1 request leaked to real origin!
        uniqueDsgNodesVisited: 4,
        successfulDeceptionInteractions: 10,
        totalDeceptionInteractions: 10,
        uniqueDecoyEndpointsTargeted: 4,
      });

      assert.strictEqual(result.originLeakage, true);
      assert.strictEqual(result.score, 0.0);
    });

    it('Correctly computes weighted partial engagement score', () => {
      const result = calculateDES({
        originLeakCount: 0,
        uniqueDsgNodesVisited: 2, // 2/4 = 0.50
        totalAccessibleDsgNodes: 4,
        successfulDeceptionInteractions: 4, // 4/5 = 0.80
        totalDeceptionInteractions: 5, // 5/10 = 0.50 dwell
        uniqueDecoyEndpointsTargeted: 2, // 2/4 = 0.50
        totalDecoyEndpoints: 4,
        dwellTargetInteractions: 10,
      });

      // Expected: 0.30*0.5 + 0.30*0.8 + 0.25*0.5 + 0.15*0.5
      // = 0.15 + 0.24 + 0.125 + 0.075 = 0.59
      assert.strictEqual(result.score, 0.59);
      assert.strictEqual(result.components.depthScore, 0.5);
      assert.strictEqual(result.components.consistencyScore, 0.8);
      assert.strictEqual(result.components.dwellScore, 0.5);
      assert.strictEqual(result.components.engagementScore, 0.5);
    });
  });
});
