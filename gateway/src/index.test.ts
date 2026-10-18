import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import http from 'node:http';
import request from 'supertest';
import { createApp } from './app';
import { app as testOriginApp } from '../test-origin/src/index.js';
import { validateOriginUrl } from './config';
import { sanitizeHeaders } from './logger';

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
});
