import { describe, it, before, after, beforeEach } from 'node:test';
import assert from 'node:assert';
import http from 'node:http';
import request from 'supertest';
import { createApp } from './app';
import { evaluateRoutingPolicy, ControllerInput } from './controller';
import { SessionRoutingStore } from './sessionRouter';
import { MetricsCollector } from './metrics';
import { SecurityEventRecorder } from './eventRecorder';

describe('Stage 11: Routing Semantics & Session Behavior Regression Tests', () => {
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
  let lastOriginReceivedRequest: any = null;

  // Mock detection response control
  let mockRiskScore = 0.05;
  let mockClassification: 'BENIGN' | 'SUSPICIOUS' | 'MALICIOUS' | 'UNAVAILABLE' = 'BENIGN';
  let mockEvidence: string[] = [];

  let sessionRouter: SessionRoutingStore;
  let metricsCollector: MetricsCollector;
  let eventRecorder: SecurityEventRecorder;
  let gatewayApp: any;

  before(async () => {
    // 1. Upstream Authorized Origin Server
    await new Promise<void>((resolve) => {
      originServer = http.createServer((req, res) => {
        originHitCount++;
        let body = '';
        req.on('data', (chunk) => { body += chunk; });
        req.on('end', () => {
          lastOriginReceivedRequest = {
            url: req.url,
            method: req.method,
            headers: req.headers,
            body,
          };
          res.setHeader('Content-Type', 'application/json');
          res.setHeader('X-Origin-Id', 'authorized-origin');
          res.writeHead(200);
          res.end(JSON.stringify({ status: 'ok', destination: 'ORIGIN', originHitCount }));
        });
      });
      originServer.listen(0, '127.0.0.1', () => {
        const addr = originServer.address() as any;
        originPort = addr.port;
        originUrl = `http://127.0.0.1:${originPort}`;
        resolve();
      });
    });

    // 2. ML Detection Mock Server
    await new Promise<void>((resolve) => {
      detectionServer = http.createServer((req, res) => {
        detectionHitCount++;
        let body = '';
        req.on('data', (chunk) => { body += chunk; });
        req.on('end', () => {
          res.setHeader('Content-Type', 'application/json');
          res.writeHead(200);
          res.end(
            JSON.stringify({
              request_id: 'req-mock',
              risk_score: mockRiskScore,
              classification: mockClassification,
              confidence: 0.95,
              evidence: mockEvidence,
              inference_duration_ms: 1.0,
            })
          );
        });
      });
      detectionServer.listen(0, '127.0.0.1', () => {
        const addr = detectionServer.address() as any;
        detectionPort = addr.port;
        detectionUrl = `http://127.0.0.1:${detectionPort}`;
        resolve();
      });
    });

    // 3. Deception Runtime Mock Server
    await new Promise<void>((resolve) => {
      deceptionServer = http.createServer((req, res) => {
        deceptionHitCount++;
        res.setHeader('Content-Type', 'application/json');
        res.setHeader('X-Deception-Node', 'DISCOVERY');
        res.writeHead(200);
        res.end(JSON.stringify({ status: 'synthetic', destination: 'DECEPTION', deceptionHitCount }));
      });
      deceptionServer.listen(0, '127.0.0.1', () => {
        const addr = deceptionServer.address() as any;
        deceptionPort = addr.port;
        deceptionUrl = `http://127.0.0.1:${deceptionPort}`;
        resolve();
      });
    });

    // 4. Initialize Gateway with Active Routing
    sessionRouter = new SessionRoutingStore(60000, 1000);
    metricsCollector = new MetricsCollector();
    eventRecorder = new SecurityEventRecorder(null, 'http://127.0.0.1:4000', 'secret');

    gatewayApp = createApp(
      {
        originUrl,
        allowedOrigins: [originUrl, deceptionUrl],
        proxyTimeoutMs: 2000,
        maxRequestBodySize: 65536,
        detectionServiceUrl: detectionUrl,
        detectionTimeoutMs: 1500,
        detectionEnabled: true,
        deceptionServiceUrl: deceptionUrl,
        routingMode: 'active',
        emergencyDisableDiversion: false,
        deceptionScoreThreshold: 0.70,
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

  beforeEach(() => {
    originHitCount = 0;
    deceptionHitCount = 0;
    detectionHitCount = 0;
    lastOriginReceivedRequest = null;
    sessionRouter.clearAllAssignments();
    mockRiskScore = 0.05;
    mockClassification = 'BENIGN';
    mockEvidence = [];
  });

  describe('1. Controller Policy: Explicit Routing Targets (ORIGIN, OBSERVE_ONLY, DECEPTION)', () => {
    it('returns ORIGIN for benign requests (< 0.40)', () => {
      const decision = evaluateRoutingPolicy({
        riskScore: 0.15,
        classification: 'BENIGN',
        evidence: [],
        sessionId: 'sess_1',
        hasExistingDeceptionAssignment: false,
        routingMode: 'active',
        emergencyDisableDiversion: false,
        deceptionScoreThreshold: 0.70,
      });
      assert.strictEqual(decision.target, 'ORIGIN');
      assert.strictEqual(decision.diverted, false);
      assert.strictEqual(decision.reason, 'BENIGN_EVALUATION');
    });

    it('returns OBSERVE_ONLY for suspicious scores (0.40 <= score < 0.70)', () => {
      const decision = evaluateRoutingPolicy({
        riskScore: 0.55,
        classification: 'SUSPICIOUS',
        evidence: ['SUSPICIOUS_PATH_PATTERN'],
        sessionId: 'sess_2',
        hasExistingDeceptionAssignment: false,
        routingMode: 'active',
        emergencyDisableDiversion: false,
        deceptionScoreThreshold: 0.70,
      });
      assert.strictEqual(decision.target, 'OBSERVE_ONLY');
      assert.strictEqual(decision.diverted, false);
      assert.strictEqual(decision.reason, 'SUSPICIOUS_OBSERVE_ONLY');
    });

    it('returns OBSERVE_ONLY for high score with insufficient corroboration (< 2 evidence, score < 0.75)', () => {
      const decision = evaluateRoutingPolicy({
        riskScore: 0.71,
        classification: 'MALICIOUS',
        evidence: ['SINGLE_WEAK_SIGNAL'],
        sessionId: 'sess_3',
        hasExistingDeceptionAssignment: false,
        routingMode: 'active',
        emergencyDisableDiversion: false,
        deceptionScoreThreshold: 0.70,
      });
      assert.strictEqual(decision.target, 'OBSERVE_ONLY');
      assert.strictEqual(decision.diverted, false);
      assert.strictEqual(decision.reason, 'INSUFFICIENT_CORROBORATION_OBSERVE_ONLY');
    });

    it('returns DECEPTION for high-confidence multi-evidence malicious signals (score >= 0.70, evidence >= 2)', () => {
      const decision = evaluateRoutingPolicy({
        riskScore: 0.85,
        classification: 'MALICIOUS',
        evidence: ['SQL_INJECTION_KEYWORD', 'HIGH_PATH_ENTROPY'],
        sessionId: 'sess_4',
        hasExistingDeceptionAssignment: false,
        routingMode: 'active',
        emergencyDisableDiversion: false,
        deceptionScoreThreshold: 0.70,
      });
      assert.strictEqual(decision.target, 'DECEPTION');
      assert.strictEqual(decision.diverted, true);
      assert.strictEqual(decision.reason, 'HIGH_CONFIDENCE_MALICIOUS_DIVERT');
    });

    it('returns DECEPTION for score >= 0.75 even with single evidence', () => {
      const decision = evaluateRoutingPolicy({
        riskScore: 0.80,
        classification: 'MALICIOUS',
        evidence: ['DEFINITIVE_RCE_TOKEN'],
        sessionId: 'sess_5',
        hasExistingDeceptionAssignment: false,
        routingMode: 'active',
        emergencyDisableDiversion: false,
        deceptionScoreThreshold: 0.70,
      });
      assert.strictEqual(decision.target, 'DECEPTION');
      assert.strictEqual(decision.diverted, true);
      assert.strictEqual(decision.reason, 'HIGH_CONFIDENCE_MALICIOUS_DIVERT');
    });

    it('returns ORIGIN in shadow mode even if score is 0.99 with multi-evidence', () => {
      const decision = evaluateRoutingPolicy({
        riskScore: 0.99,
        classification: 'MALICIOUS',
        evidence: ['SQL_INJECTION_KEYWORD', 'HIGH_PATH_ENTROPY'],
        sessionId: 'sess_6',
        hasExistingDeceptionAssignment: false,
        routingMode: 'shadow',
        emergencyDisableDiversion: false,
        deceptionScoreThreshold: 0.70,
      });
      assert.strictEqual(decision.target, 'ORIGIN');
      assert.strictEqual(decision.diverted, false);
      assert.strictEqual(decision.reason, 'SHADOW_MODE_ACTIVE');
    });

    it('returns ORIGIN when emergency killswitch is active', () => {
      const decision = evaluateRoutingPolicy({
        riskScore: 0.95,
        classification: 'MALICIOUS',
        evidence: ['CMD_INJECTION'],
        sessionId: 'sess_7',
        hasExistingDeceptionAssignment: true,
        routingMode: 'active',
        emergencyDisableDiversion: true,
        deceptionScoreThreshold: 0.70,
      });
      assert.strictEqual(decision.target, 'ORIGIN');
      assert.strictEqual(decision.diverted, false);
      assert.strictEqual(decision.reason, 'EMERGENCY_DISABLE_ACTIVE');
    });
  });

  describe('2. Physical Upstream Routing Invariants: OBSERVE_ONLY vs ORIGIN vs DECEPTION', () => {
    it('ORIGIN request physically routes to authorized origin server', async () => {
      mockRiskScore = 0.05;
      mockClassification = 'BENIGN';

      const res = await request(gatewayApp)
        .get('/api/catalog')
        .set('x-session-id', 'sess_test_origin_1');

      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.headers['x-routing-decision'], 'ORIGIN');
      assert.strictEqual(originHitCount, 1, 'Origin server must be hit');
      assert.strictEqual(deceptionHitCount, 0, 'Deception server must NOT be hit');
      assert.strictEqual(res.body.destination, 'ORIGIN');
    });

    it('OBSERVE_ONLY request PHYSICALLY ROUTES TO ORIGIN SERVER (constituting an origin leak if malicious)', async () => {
      mockRiskScore = 0.55;
      mockClassification = 'SUSPICIOUS';
      mockEvidence = ['SUSPICIOUS_PATH'];

      const res = await request(gatewayApp)
        .post('/api/catalog/search')
        .set('x-session-id', 'sess_test_observe_1')
        .send({ query: 'suspicious probe' });

      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.headers['x-routing-decision'], 'OBSERVE_ONLY');
      assert.strictEqual(originHitCount, 1, 'OBSERVE_ONLY request MUST physically reach the origin server');
      assert.strictEqual(deceptionHitCount, 0, 'OBSERVE_ONLY request must NOT reach deception');
      assert.strictEqual(res.body.destination, 'ORIGIN');
      assert.ok(lastOriginReceivedRequest, 'Origin received request');
      assert.strictEqual(lastOriginReceivedRequest.url, '/api/catalog/search');

      // Crucial security invariant: sessionRouter is NOT assigned to deception
      assert.strictEqual(sessionRouter.isSessionAssignedToDeception('sess_test_observe_1'), false);
    });

    it('DECEPTION request physically routes to deception runtime, completely shielding origin', async () => {
      mockRiskScore = 0.92;
      mockClassification = 'MALICIOUS';
      mockEvidence = ['SQL_INJECTION', 'ENTROPY'];

      const res = await request(gatewayApp)
        .post('/api/users')
        .set('x-session-id', 'sess_test_decept_1')
        .send({ name: "' OR 1=1--" });

      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.headers['x-routing-decision'], 'DECEPTION');
      assert.strictEqual(deceptionHitCount, 1, 'Deception server must be hit');
      assert.strictEqual(originHitCount, 0, 'Origin server must NOT be touched');
      assert.strictEqual(res.body.destination, 'DECEPTION');
      assert.strictEqual(res.headers['x-deception-node'], 'DISCOVERY');
    });
  });

  describe('3. Multi-Request Session Behavior & Stickiness Semantics', () => {
    it('maintains session stickiness: subsequent benign requests from a flagged session remain in deception', async () => {
      const sessionId = 'sess_attacker_sequence_1';

      // Step 1: Malicious probe causes diversion
      mockRiskScore = 0.90;
      mockClassification = 'MALICIOUS';
      mockEvidence = ['SQLI', 'PATH_TRAVERSAL'];

      const res1 = await request(gatewayApp)
        .get('/api/users/profile')
        .set('x-session-id', sessionId);

      assert.strictEqual(res1.status, 200);
      assert.strictEqual(res1.headers['x-routing-decision'], 'DECEPTION');
      assert.strictEqual(res1.headers['x-routing-reason'], 'HIGH_CONFIDENCE_MALICIOUS_DIVERT');
      assert.strictEqual(deceptionHitCount, 1);
      assert.strictEqual(originHitCount, 0);

      // Verify sticky assignment is stored
      assert.strictEqual(sessionRouter.isSessionAssignedToDeception(sessionId), true);

      // Step 2: Same session sends a benign-looking request (low score)
      mockRiskScore = 0.05;
      mockClassification = 'BENIGN';
      mockEvidence = [];

      const res2 = await request(gatewayApp)
        .get('/api/catalog')
        .set('x-session-id', sessionId);

      assert.strictEqual(res2.status, 200);
      assert.strictEqual(res2.headers['x-routing-decision'], 'DECEPTION');
      assert.strictEqual(res2.headers['x-routing-reason'], 'STICKY_SESSION_ASSIGNMENT');
      assert.strictEqual(deceptionHitCount, 2, 'Follow-up request must remain in deception');
      assert.strictEqual(originHitCount, 0, 'Origin must remain completely protected');

      // Step 3: A DIFFERENT session sends the same benign request -> correctly reaches origin
      const res3 = await request(gatewayApp)
        .get('/api/catalog')
        .set('x-session-id', 'sess_innocent_user_1');

      assert.strictEqual(res3.status, 200);
      assert.strictEqual(res3.headers['x-routing-decision'], 'ORIGIN');
      assert.strictEqual(originHitCount, 1, 'Innocent user reaches origin');
      assert.strictEqual(deceptionHitCount, 2, 'Deception hit count unchanged');
    });

    it('demonstrates Variant D failure mode (Stateless Evaluation): disabling stickiness causes probe leaks to origin', async () => {
      // Create a stateless gateway where sessionRouter is NOT utilized (or cleared every request)
      const statelessSessionRouter = new SessionRoutingStore(60000, 1000);
      const statelessApp = createApp(
        {
          originUrl,
          allowedOrigins: [originUrl, deceptionUrl],
          proxyTimeoutMs: 2000,
          maxRequestBodySize: 65536,
          detectionServiceUrl: detectionUrl,
          detectionTimeoutMs: 1500,
          detectionEnabled: true,
          deceptionServiceUrl: deceptionUrl,
          routingMode: 'active',
          emergencyDisableDiversion: false,
          deceptionScoreThreshold: 0.70,
          deceptionFailurePolicy: 'quarantine',
        },
        statelessSessionRouter,
        metricsCollector,
        eventRecorder
      );

      const sessionId = 'sess_variant_d_attacker';

      // Step 1: High-confidence attack diverted
      mockRiskScore = 0.90;
      mockClassification = 'MALICIOUS';
      mockEvidence = ['CMDI', 'ENTROPY'];

      const res1 = await request(statelessApp)
        .post('/api/admin')
        .set('x-session-id', sessionId)
        .send({ cmd: 'whoami' });

      assert.strictEqual(res1.headers['x-routing-decision'], 'DECEPTION');
      assert.strictEqual(deceptionHitCount, 1);
      assert.strictEqual(originHitCount, 0);

      // In Variant D, stickiness is explicitly cleared / disregarded
      statelessSessionRouter.resetSessionAssignment(sessionId);
      assert.strictEqual(statelessSessionRouter.isSessionAssignedToDeception(sessionId), false);

      // Step 2: Attacker sends subtle probe (score 0.55 -> SUSPICIOUS)
      mockRiskScore = 0.55;
      mockClassification = 'SUSPICIOUS';
      mockEvidence = ['SUBTLE_PROBE'];

      const res2 = await request(statelessApp)
        .get('/api/catalog?q=probe')
        .set('x-session-id', sessionId);

      // Because stickiness was absent, request falls to OBSERVE_ONLY and LEAKS TO ORIGIN!
      assert.strictEqual(res2.headers['x-routing-decision'], 'OBSERVE_ONLY');
      assert.strictEqual(originHitCount, 1, 'Stateless routing caused attack probe to LEAK to origin');
      assert.strictEqual(res2.body.destination, 'ORIGIN');
    });
  });

  describe('4. Session Router Operational Controls: Reset & TTL Expiration', () => {
    it('allows operator to reset a session deception assignment', () => {
      sessionRouter.assignSessionToDeception('sess_reset_me', 'TEST', 0.9);
      assert.strictEqual(sessionRouter.isSessionAssignedToDeception('sess_reset_me'), true);

      const removed = sessionRouter.resetSessionAssignment('sess_reset_me');
      assert.strictEqual(removed, true);
      assert.strictEqual(sessionRouter.isSessionAssignedToDeception('sess_reset_me'), false);
    });

    it('expires stale sessions after TTL', async () => {
      const shortTtlRouter = new SessionRoutingStore(20, 100); // 20ms TTL
      shortTtlRouter.assignSessionToDeception('sess_short_lived', 'TEST', 0.9);
      assert.strictEqual(shortTtlRouter.isSessionAssignedToDeception('sess_short_lived'), true);

      await new Promise((r) => setTimeout(r, 30));
      assert.strictEqual(shortTtlRouter.isSessionAssignedToDeception('sess_short_lived'), false);
    });
  });
});
