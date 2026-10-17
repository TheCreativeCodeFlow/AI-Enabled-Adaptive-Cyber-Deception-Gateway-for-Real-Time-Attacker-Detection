import { describe, it } from 'node:test';
import assert from 'node:assert';
import request from 'supertest';
import { app } from './app';

describe('Backend Health & Core Endpoints', () => {
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
