import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import http from 'node:http';
import request from 'supertest';
import { createApp } from './app';
import { app as testOriginApp } from '../test-origin/src/index.js';
import { validateOriginUrl } from './config';
import { sanitizeHeaders } from './logger';

describe('Stage 2: Secure Reverse-Proxy Gateway', () => {
  let originServer: http.Server;
  let originPort: number;
  let originUrl: string;
  let gatewayApp: any;

  before(async () => {
    // Spin up an in-memory test-origin server on an ephemeral port
    await new Promise<void>((resolve) => {
      originServer = testOriginApp.listen(0, '127.0.0.1', () => {
        const address = originServer.address() as any;
        originPort = address.port;
        originUrl = `http://127.0.0.1:${originPort}`;
        resolve();
      });
    });

    // Create gateway pointing to this authorized test origin
    gatewayApp = createApp({
      originUrl,
      allowedOrigins: [originUrl, 'http://test-origin:5000', 'http://localhost:5000'],
      proxyTimeoutMs: 1000,
      maxRequestBodySize: 1024, // 1KB for testing limit
    });
  });

  after(async () => {
    await new Promise<void>((resolve) => originServer.close(() => resolve()));
  });

  describe('1. Health Check & Local Routes', () => {
    it('GET /health returns HTTP 200 with valid gateway JSON metadata', async () => {
      const res = await request(gatewayApp).get('/health');
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.headers['content-type'].includes('application/json'), true);
      assert.strictEqual(res.body.status, 'healthy');
      assert.strictEqual(res.body.service, 'gateway');
      assert.strictEqual(res.body.stage, 'Stage 2 — Secure Reverse-Proxy Gateway');
      assert.strictEqual(res.body.upstream, originUrl);
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

  describe('3. Negative Security & Error Handling Tests', () => {
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
      // Create gateway instance pointing to a dead port
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
      // Request /api/delay/2000 while timeout is 500ms
      const timeoutGateway = createApp({
        originUrl,
        allowedOrigins: [originUrl],
        proxyTimeoutMs: 400, // 400ms timeout
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

      // The request MUST still reach the authorized test origin
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

      // Approved origin
      const valid = validateOriginUrl('http://test-origin:5000', allowed);
      assert.strictEqual(valid.origin, 'http://test-origin:5000');

      // Unapproved origin (SSRF attempt)
      assert.throws(
        () => validateOriginUrl('http://169.254.169.254/latest/meta-data', allowed),
        /Forbidden ORIGIN_URL/
      );

      // Malicious external domain
      assert.throws(
        () => validateOriginUrl('http://evil.com', allowed),
        /Forbidden ORIGIN_URL/
      );

      // Invalid protocol
      assert.throws(
        () => validateOriginUrl('ftp://test-origin:5000', allowed),
        /Invalid ORIGIN_URL protocol/
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
