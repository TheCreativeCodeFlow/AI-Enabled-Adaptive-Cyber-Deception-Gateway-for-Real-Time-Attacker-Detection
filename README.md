# AI-Enabled Adaptive Cyber Deception Gateway for Real-Time Attacker Detection

> **Current Status: Stage 2 — Secure Reverse-Proxy Gateway**

A modular, adaptive cyber deception platform that identifies malicious network traffic using machine learning and diverts adversaries into isolated, high-interaction honeypots in real time.

---

## 1. Project Structure

```
.
├── gateway/               # [Stage 2 — Active] Secure HTTP reverse-proxy gateway
│   ├── src/               # Application code (app.ts, proxy.ts, config.ts, logger.ts, index.test.ts)
│   ├── test-origin/       # Authorized internal test origin (unexposed to host)
│   ├── Dockerfile         # Multi-stage container build
│   └── package.json       # Dependencies & test scripts
├── backend/               # [Stage 1 — Active] Node.js, Express & TypeScript core service
│   ├── src/               # Application code (app.ts, index.ts, index.test.ts)
│   ├── Dockerfile         # Multi-stage container build
│   └── package.json       # Dependencies & test scripts
├── frontend/              # [Stage 1 — Active] React with JavaScript and Vite
│   ├── src/               # React components (App.jsx, main.jsx, index.css)
│   ├── Dockerfile         # Container build with lightweight static server
│   ├── vite.config.js     # Vite configuration
│   └── package.json       # Dependencies & build scripts
├── detection/             # [Reserved — Stage 3] Python ML anomaly detection service
├── deception/             # [Reserved — Stage 4] Isolated honeypots & decoy runtime
├── infra/                 # Docker Compose & local infrastructure configuration
├── docs/                  # Architecture specifications and documentation
│   └── architecture.md    # System architecture, trust boundaries & roadmap
├── docker-compose.yml     # Local multi-service orchestration
├── .env.example           # Environment template
└── .gitignore             # Ignored files and secrets
```

---

## 2. Prerequisites

- **Node.js**: `v20.0.0` or higher (`node -v`)
- **npm**: `v10.0.0` or higher (`npm -v`)
- **Docker**: `20.10+` with Compose v2 support (`docker compose` or `docker-compose`)

---

## 3. Quickstart with Docker Compose

### 3.1 Setup Environment
Copy the example environment file:
```bash
cp .env.example .env
```

### 3.2 Build and Start Services
Start all 5 services in detached mode:
```bash
docker compose up -d --build
```
*(Or `docker-compose up -d --build`)*

### 3.3 Verify Service Health
Check that all services are running and report healthy status:
```bash
docker compose ps
```

You should see:
- `deception-gateway`: `healthy` (port 8080)
- `deception-test-origin`: `healthy` (internal port 5000, no published host port)
- `deception-backend`: `healthy` (port 4000)
- `deception-frontend`: `healthy` (port 3000)
- `deception-postgres`: `healthy` (port 5432)

### 3.4 View Logs
```bash
# Follow logs across all services
docker compose logs -f

# Follow specific service logs
docker compose logs -f gateway
docker compose logs -f test-origin
docker compose logs -f backend
docker compose logs -f frontend
docker compose logs -f postgres
```

### 3.5 Stop and Clean Up
```bash
# Stop containers
docker compose stop

# Stop and remove containers and networks
docker compose down

# Stop, remove containers, and purge volumes
docker compose down -v
```

---

## 4. Local Development (Without Docker)

You can run individual services directly on the host machine.

### Gateway (Reverse Proxy)
```bash
cd gateway

# 1. Install dependencies
npm install

# 2. Run unit & negative security tests
npm test

# 3. Build TypeScript
npm run build

# 4. Start in development mode (pointing to test-origin)
ORIGIN_URL=http://localhost:5000 npm run dev
```

### Test Origin Service
```bash
cd gateway/test-origin
npm install
npm start
```
- Test Origin starts on `http://localhost:5000`

### Backend (Node.js + Express + TypeScript)
```bash
cd backend
npm install
npm test
npm run build
npm run dev
```
- Health Check: `http://localhost:4000/health`

### Frontend (React + Vite)
```bash
cd frontend
npm install
npm run dev
```
- Web UI: `http://localhost:3000`

---

## 5. Verification & Testing

### 5.1 Gateway Health Endpoint
```bash
curl -i http://localhost:8080/health
```
Expected JSON Response (`HTTP 200 OK`):
```json
{
  "status": "healthy",
  "service": "gateway",
  "stage": "Stage 2 — Secure Reverse-Proxy Gateway",
  "upstream": "http://test-origin:5000",
  "timestamp": "...",
  "uptime": 24.69
}
```

### 5.2 Upstream Request Forwarding
```bash
# Root proxy request to test origin
curl -i http://localhost:8080/

# Query parameters forwarding
curl -i "http://localhost:8080/api/echo?filter=security&page=1"

# POST JSON forwarding (preserves cookies and custom headers)
curl -i -X POST http://localhost:8080/api/echo \
  -H "Content-Type: application/json" \
  -d '{"probe": false, "scenario": "verification"}'

# Origin non-200 status code forwarding
curl -i http://localhost:8080/api/status/403
curl -i http://localhost:8080/api/status/500
```

### 5.3 Negative Security & Error Handling Checks
```bash
# 1. Path traversal attempt (rejected with 400 Bad Request)
curl -i --path-as-is http://localhost:8080/../../etc/passwd

# 2. Request body exceeding 1MB limit (rejected with 413 Payload Too Large)
curl -i -X POST http://localhost:8080/api/echo -H "Content-Length: 2000000" --data "test"

# 3. Host header spoofing / SSRF attempt (safely routed only to authorized test origin)
curl -i http://localhost:8080/api/echo \
  -H "Host: 169.254.169.254" \
  -H "X-Forwarded-Host: evil-attacker.com"

# 4. Origin isolation check (test-origin has no published host port)
curl -i http://localhost:5000
```

### 5.4 Automated Test Suites
```bash
# Gateway unit, integration, and security tests
cd gateway && npm test

# Backend unit & health tests
cd backend && npm test

# Frontend production build verification
cd frontend && npm run build
```

---

## 6. Environment Variables

| Variable | Description | Default | Service |
|---|---|---|---|
| `GATEWAY_PORT` | Gateway HTTP listening port | `8080` | Gateway |
| `ORIGIN_URL` | Upstream target origin URL | `http://test-origin:5000` | Gateway |
| `ALLOWED_ORIGINS` | Comma-separated whitelist of approved origins | `http://test-origin:5000,http://localhost:5000,http://127.0.0.1:5000` | Gateway |
| `PROXY_TIMEOUT_MS` | Proxy request timeout in milliseconds | `5000` | Gateway |
| `MAX_REQUEST_BODY_SIZE` | Maximum permitted request body size in bytes | `1048576` (1MB) | Gateway |
| `PORT` | Backend HTTP listening port | `4000` | Backend |
| `HOST` | Bind host address | `0.0.0.0` | Gateway/Backend |
| `NODE_ENV` | Environment mode (`development`/`production`) | `production` | All |
| `CORS_ORIGIN` | Allowed origin for CORS requests | `http://localhost:3000` | Backend |
| `FRONTEND_PORT` | Frontend HTTP listening port | `3000` | Frontend |
| `VITE_BACKEND_URL` | Backend API URL for frontend client | `http://localhost:4000` | Frontend |
| `VITE_GATEWAY_URL` | Gateway URL for frontend client | `http://localhost:8080` | Frontend |
| `POSTGRES_USER` | PostgreSQL superuser username | `deception_user` | Database |
| `POSTGRES_PASSWORD`| PostgreSQL superuser password | `deception_pass` | Database |
| `POSTGRES_DB` | PostgreSQL default database | `deception_db` | Database |
| `POSTGRES_PORT` | PostgreSQL external host port | `5432` | Database |
| `DATABASE_URL` | Full database connection string | `postgresql://...` | Backend/DB |

> **Security Notice:** Never commit `.env` or production credentials to Git. Use `.env.example` as a template for local overrides.

---

## 7. Next Stage: Stage 3 Preview

- **Stage 3: ML Detection Engine (`detection/`)**
  - Implement Python-based ML detection service.
  - Request feature extraction (payload entropy, path anomalies, header patterns).
  - Anomaly detection scoring API with confidence scores.
  - Streaming telemetry hooks connecting the Stage 2 Gateway to the ML Detection service.
