# Gateway Service (Stage 2 — Secure Reverse-Proxy Gateway)

## 1. Overview
The `gateway/` service acts as the perimeter reverse-proxy ingress point for all incoming network traffic. It establishes the secure traffic forwarding path required for subsequent AI-enabled threat detection (Stage 3) and dynamic deception diversion (Stage 4).

In Stage 2, the gateway receives client requests and proxies them strictly to an authorized, fixed internal test origin (`http://test-origin:5000`) within Docker's isolated network.

---

## 2. Key Responsibilities & Features

- **Strict Upstream Whitelisting:** The gateway only forwards traffic to explicitly permitted local origins configured via `ORIGIN_URL` and `ALLOWED_ORIGINS`. Clients can never supply, manipulate, or override the upstream destination host.
- **SSRF & Open-Proxy Prevention:** Headers such as `Host`, `X-Forwarded-Host`, `X-Proxy-Target`, or query parameters are ignored for destination routing. Loopback addresses, cloud metadata endpoints (`169.254.169.254`), and unauthorized domains are rejected.
- **Path Traversal Defense:** Sanitizes and rejects traversal sequences (`..`, `%2e%2e`, null bytes) with `400 Bad Request`.
- **Payload Size Enforcement:** Rejects requests exceeding `MAX_REQUEST_BODY_SIZE` (default 1MB) with `413 Payload Too Large` via both `Content-Length` inspection and streaming body byte tracking.
- **Proxy Timeouts & Controlled Failures:**
  - Upstream timeout triggers `504 Gateway Timeout` after `PROXY_TIMEOUT_MS` (default 5000ms).
  - Unreachable/offline origin triggers `502 Bad Gateway` without crashing the gateway or leaking stack traces.
- **Request Tracking & Header Preservation:** Generates or propagates `X-Request-ID` across requests, preserves legitimate response headers, cookies (`Set-Cookie`), and status codes.
- **Structured Zero-Leakage Logging:** Emits JSON metadata logs including request ID, method, path, status, and duration. Headers such as `Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`, and API keys are strictly redacted (`[REDACTED]`). Raw request bodies are never logged.

---

## 3. Configuration

Configured via environment variables:

| Variable | Description | Default |
|---|---|---|
| `PORT` | Gateway HTTP listening port | `8080` |
| `HOST` | Bind host address | `0.0.0.0` |
| `ORIGIN_URL` | Fixed upstream target URL | `http://test-origin:5000` |
| `ALLOWED_ORIGINS` | Comma-separated list of approved target origins | `http://test-origin:5000,http://localhost:5000,http://127.0.0.1:5000` |
| `PROXY_TIMEOUT_MS` | Maximum upstream wait duration in milliseconds | `5000` |
| `MAX_REQUEST_BODY_SIZE` | Maximum permitted request body size in bytes | `1048576` (1MB) |

---

## 4. Endpoints

### 4.1 Gateway Health
- **Endpoint:** `GET /health`
- **Description:** Handled locally by the gateway without proxying to upstream.
- **Response:**
  ```json
  {
    "status": "healthy",
    "service": "gateway",
    "stage": "Stage 2 — Secure Reverse-Proxy Gateway",
    "upstream": "http://test-origin:5000",
    "timestamp": "2026-10-17T17:37:12.579Z",
    "uptime": 24.69
  }
  ```

### 4.2 Proxy Traffic Path
- **Endpoints:** All other routes (e.g., `GET /`, `POST /api/echo`, etc.)
- **Forwarded Target:** Fixed to `ORIGIN_URL` (`http://test-origin:5000`)

---

## 5. Local Testing

```bash
# 1. Install dependencies
npm install

# 2. Run unit & negative security tests
npm test

# 3. Build TypeScript
npm run build
```
