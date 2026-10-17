import express from 'express';

export const app = express();
const PORT = parseInt(process.env.PORT || '5000', 10);
const HOST = process.env.HOST || '0.0.0.0';

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Root identifiable test endpoint
app.get('/', (req, res) => {
  res.setHeader('X-Origin-ID', 'authorized-test-origin');
  res.json({
    origin: 'test-origin',
    service: 'authorized-test-origin',
    message: 'Response from authorized test origin',
    path: req.path,
    timestamp: new Date().toISOString(),
  });
});

// Origin health check
app.get('/health', (_req, res) => {
  res.json({
    status: 'healthy',
    service: 'test-origin',
    uptime: process.uptime(),
  });
});

// Echo query and headers
app.get('/api/echo', (req, res) => {
  res.setHeader('X-Origin-ID', 'authorized-test-origin');
  res.json({
    origin: 'test-origin',
    method: 'GET',
    query: req.query,
    headers: {
      'x-request-id': req.headers['x-request-id'],
      'user-agent': req.headers['user-agent'],
      'x-forwarded-for': req.headers['x-forwarded-for'],
    },
  });
});

// Echo POST body and set cookie & custom header
app.post('/api/echo', (req, res) => {
  res.setHeader('X-Origin-ID', 'authorized-test-origin');
  res.setHeader('X-Origin-Custom-Header', 'stage2-verified');
  res.setHeader('Set-Cookie', 'origin_session=stage2_test_cookie_123; Path=/; HttpOnly');
  res.status(201).json({
    origin: 'test-origin',
    method: 'POST',
    received: req.body,
    contentType: req.headers['content-type'],
  });
});

// Return arbitrary non-200 status code for testing error forwarding
app.get('/api/status/:code', (req, res) => {
  const code = parseInt(req.params.code, 10) || 400;
  res.setHeader('X-Origin-ID', 'authorized-test-origin');
  res.status(code).json({
    origin: 'test-origin',
    error: `Simulated origin error status ${code}`,
    code,
  });
});

// Delayed response for testing proxy timeout
app.get('/api/delay/:ms', (req, res) => {
  const ms = parseInt(req.params.ms, 10) || 1000;
  setTimeout(() => {
    res.setHeader('X-Origin-ID', 'authorized-test-origin');
    res.json({
      origin: 'test-origin',
      delayedMs: ms,
    });
  }, ms);
});

// If executed directly, start server
if (process.argv[1] && process.argv[1].endsWith('index.js')) {
  const server = app.listen(PORT, HOST, () => {
    console.log(`[Test-Origin] Listening on http://${HOST}:${PORT}`);
  });

  const shutdown = (signal) => {
    console.log(`[Test-Origin] Received ${signal}, exiting...`);
    server.close(() => process.exit(0));
  };
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}
