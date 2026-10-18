# AI-Enabled Adaptive Cyber Deception Gateway for Real-Time Attacker Detection

> **Current Status: Stage 3 — ML Detection Engine and Gateway Integration**

A modular, adaptive cyber deception platform that identifies malicious network traffic using machine learning and diverts adversaries into isolated, high-interaction honeypots in real time.

---

## 1. Project Structure

```
.
├── gateway/               # [Stage 2 & 3 — Active] Secure HTTP reverse proxy & feature extractor
│   ├── src/               # Code (app.ts, proxy.ts, detector.ts, features.ts, config.ts, logger.ts)
│   ├── test-origin/       # Authorized internal test origin (unexposed to host)
│   ├── Dockerfile         # Multi-stage container build
│   └── package.json       # Dependencies & test scripts
├── detection/             # [Stage 3 — Active] Python FastAPI ML anomaly detection service
│   ├── src/               # Application code (main.py, schemas.py, deterministic.py, ml_model.py, dataset.py)
│   ├── tests/             # Pytest test suite (test_detection.py)
│   ├── train.py           # Reproducible model training pipeline
│   ├── model.joblib       # Serialized StandardScaler + RandomForest pipeline
│   ├── requirements.txt   # Python dependencies
│   ├── Dockerfile         # Python 3.11 container build
│   └── README.md          # Model specifications, feature schema & synthetic data limitations
├── backend/               # [Stage 1 — Active] Node.js, Express & TypeScript core service
│   ├── src/               # Application code (app.ts, index.ts, index.test.ts)
│   ├── Dockerfile         # Multi-stage container build
│   └── package.json       # Dependencies & test scripts
├── frontend/              # [Stage 1 — Active] React with JavaScript and Vite operator console
│   ├── src/               # React components (App.jsx, main.jsx, index.css)
│   ├── Dockerfile         # Container build with lightweight static server
│   ├── vite.config.js     # Vite configuration
│   └── package.json       # Dependencies & build scripts
├── deception/             # [Reserved — Stage 4] Isolated honeypots & decoy runtime
├── infra/                 # Docker Compose & local infrastructure configuration
├── docs/                  # Architecture specifications and documentation
│   └── architecture.md    # System architecture, trust boundaries & roadmap
├── docker-compose.yml     # Local multi-service orchestration
├── .env.example           # Environment template
└── .gitignore             # Ignored files, virtual environments, models & secrets
```

---

## 2. Prerequisites

- **Node.js**: `v20.0.0` or higher (`node -v`)
- **npm**: `v10.0.0` or higher (`npm -v`)
- **Python**: `3.10+` (for local detection development; `python3 -v`)
- **Docker**: `20.10+` with Compose v2 support (`docker compose` or `docker-compose`)

---

## 3. Quickstart with Docker Compose

### 3.1 Setup Environment
Copy the example environment file:
```bash
cp .env.example .env
```

### 3.2 Build and Start Services
Start all 6 services in detached mode:
```bash
docker compose up -d --build
```

### 3.3 Verify Service Health
Check that all services are running and report healthy status:
```bash
docker compose ps
```

You should see:
- `deception-gateway`: `healthy` (published host port `8080`)
- `deception-detection`: `healthy` (internal port `8000`, no published host port)
- `deception-test-origin`: `healthy` (internal port `5000`, no published host port)
- `deception-backend`: `healthy` (published host port `4000`)
- `deception-frontend`: `healthy` (published host port `3000`)
- `deception-postgres`: `healthy` (published host port `5432`)

### 3.4 View Logs
```bash
# Follow logs across all services
docker compose logs -f

# Follow gateway logs (includes detection inference duration and risk score)
docker compose logs -f gateway

# Follow detection engine logs
docker compose logs -f detection
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

### Gateway (Reverse Proxy + Detection Integration)
```bash
cd gateway
npm install
npm test
npm run build
ORIGIN_URL=http://localhost:5000 DETECTION_SERVICE_URL=http://localhost:8000 npm run dev
```

### Detection Service (Python ML Engine)
```bash
cd detection
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python train.py
pytest tests/test_detection.py
uvicorn src.main:app --host 0.0.0.0 --port 8000
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
  "stage": "Stage 3 — ML Detection Engine and Gateway Integration",
  "upstream": "http://test-origin:5000",
  "detectionService": "http://detection:8000",
  "detectionEnabled": true,
  "timestamp": "...",
  "uptime": 120.5
}
```

### 5.2 Shadow Mode Traffic Forwarding
In Stage 3, all requests are forwarded faithfully to the authorized upstream origin, with real-time detection headers attached.

```bash
# 1. Benign Request (classified as BENIGN, forwarded to origin)
curl -i http://localhost:8080/

# Output Headers:
# X-Detection-Score: 0.0100
# X-Detection-Classification: BENIGN
# X-Origin-ID: authorized-test-origin

# 2. Suspicious Probe (classified as SUSPICIOUS or MALICIOUS, forwarded in shadow mode)
curl -i -H "User-Agent: sqlmap/1.5.2" "http://localhost:8080/api/admin/probe?id=1%20UNION%20SELECT%20null,null--"

# Output Headers:
# X-Detection-Score: 0.3550
# X-Detection-Classification: SUSPICIOUS
# X-Origin-ID: authorized-test-origin
```

### 5.3 Zero-Leakage Privacy & Structured Logging
Inspect gateway structured logs to confirm that zero credentials, cookies, or request bodies are logged:
```bash
docker compose logs --tail=5 gateway
```
Sample log entry:
```json
{"level":"INFO","timestamp":"2026-10-18T15:36:50.497Z","requestId":"629fc0c6-7862-4f3b-93c9-a0344293b446","method":"GET","path":"/api/admin/probe?...","statusCode":200,"durationMs":19.47,"clientIp":"172.18.0.1","userAgent":"sqlmap/1.5.2","detectionScore":0.355,"detectionClassification":"SUSPICIOUS","detectionInferenceMs":14.421}
```

### 5.4 Automated Test Suites
```bash
# 1. Detection Service Pytest Suite
PYTHONPATH=detection ./detection/.venv/bin/pytest detection/tests/test_detection.py

# 2. Gateway Unit, Integration, Shadow Mode & Security Tests
cd gateway && npm test

# 3. Backend Unit & Health Tests
cd backend && npm test

# 4. Frontend Production Build Verification
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
| `DETECTION_SERVICE_URL` | Internal URL of ML detection engine | `http://detection:8000` | Gateway |
| `DETECTION_TIMEOUT_MS` | Detection request timeout before fail-open | `500` | Gateway |
| `DETECTION_ENABLED` | Enable or disable ML detection inspection | `true` | Gateway |
| `DETECTION_PORT` | Python FastAPI detection service port | `8000` | Detection |
| `PORT` | Backend HTTP listening port | `4000` | Backend |
| `HOST` | Bind host address | `0.0.0.0` | Gateway/Backend/Detection |
| `NODE_ENV` | Environment mode (`development`/`production`) | `production` | All Node |
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

## 7. Next Stage: Stage 4 Preview

- **Stage 4: Dynamic Deception Runtime (`deception/`)**
  - Implement isolated decoy containers and honeypot runtimes.
  - Gateway dynamic policy routing: transition from Stage 3 Shadow Mode to active diversion of attacker sessions (`score >= threshold`).
  - Believable mock services (fake admin dashboards, simulated SQL databases, decoy files, canary tokens).
  - Unidirectional audit telemetry streaming back to backend without network egress risks.
