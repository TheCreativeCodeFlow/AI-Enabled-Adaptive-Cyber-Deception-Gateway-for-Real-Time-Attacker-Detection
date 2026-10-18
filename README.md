# AI-Enabled Adaptive Cyber Deception Gateway for Real-Time Attacker Detection

> **Current Status: Stage 4 — Isolated Dynamic Deception Runtime and DSG**

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
│   ├── src/               # Code (main.py, schemas.py, deterministic.py, ml_model.py, dataset.py)
│   ├── tests/             # Pytest test suite (test_detection.py)
│   ├── train.py           # Reproducible model training pipeline
│   ├── model.joblib       # Serialized StandardScaler + RandomForest pipeline
│   ├── requirements.txt   # Python dependencies
│   ├── Dockerfile         # Python 3.11 container build
│   └── README.md          # Model specifications, feature schema & synthetic data limitations
├── deception/             # [Stage 4 — Active] Isolated dynamic deception runtime & DSG
│   ├── src/               # Code (app.ts, dsg.ts, policy.ts, sessionStore.ts, strategy.ts, syntheticData.ts)
│   ├── Dockerfile         # Multi-stage container build with unprivileged node user
│   ├── package.json       # Dependencies & test scripts
│   └── README.md          # DSG specifications, layer models & API contracts
├── backend/               # [Stage 1 — Active] Node.js, Express & TypeScript core service
│   ├── src/               # Application code (app.ts, index.ts, index.test.ts)
│   ├── Dockerfile         # Multi-stage container build
│   └── package.json       # Dependencies & test scripts
├── frontend/              # [Stage 1 — Active] React with JavaScript and Vite operator console
│   ├── src/               # React components (App.jsx, main.jsx, index.css)
│   ├── Dockerfile         # Container build with lightweight static server
│   ├── vite.config.js     # Vite configuration
│   └── package.json       # Dependencies & build scripts
├── infra/                 # Docker Compose & local infrastructure configuration
├── docs/                  # Architecture specifications and documentation
│   └── architecture.md    # System architecture, trust boundaries & roadmap
├── docker-compose.yml     # Local multi-service orchestration (7 services)
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
Start all 7 services in detached mode:
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
- `deception-runtime`: `healthy` (internal port `5050`, no published host port)
- `deception-test-origin`: `healthy` (internal port `5000`, no published host port)
- `deception-backend`: `healthy` (published host port `4000`)
- `deception-frontend`: `healthy` (published host port `3000`)
- `deception-postgres`: `healthy` (published host port `5432`)

### 3.4 View Logs
```bash
# Follow logs across all services
docker compose logs -f

# Follow deception runtime logs
docker compose logs -f deception

# Follow gateway logs (includes detection scores and shadow-mode status)
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

### Deception Runtime (Isolated DSG Service)
```bash
cd deception
npm install
npm test
npm run build
npm run dev
```
- Health Check: `http://localhost:5050/health`

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

### 5.1 Deception Runtime Verification
```bash
# Verify health check inside Docker network
docker exec deception-runtime node -e "fetch('http://127.0.0.1:5050/health').then(r => r.json()).then(console.log)"

# Output:
# { status: 'healthy', service: 'deception-runtime', stage: 'Stage 4 — Dynamic Deception Runtime and DSG', policyVersion: '1.0.0-immutable', ... }
```

### 5.2 Gateway Shadow Mode Traffic Forwarding
In Stage 4, gateway traffic diversion remains inactive. All requests continue to be forwarded faithfully to the authorized upstream origin with detection headers attached.

```bash
# 1. Benign Request
curl -i http://localhost:8080/

# Output Headers:
# X-Detection-Score: 0.0100
# X-Detection-Classification: BENIGN
# X-Origin-ID: authorized-test-origin

# 2. Suspicious Probe (Shadow Mode Verification)
curl -i -H "User-Agent: sqlmap/1.5.2" "http://localhost:8080/api/admin/probe?id=1%20UNION%20SELECT%20null,null--"

# Output Headers:
# X-Detection-Score: 0.3550
# X-Detection-Classification: SUSPICIOUS
# X-Origin-ID: authorized-test-origin
```

### 5.3 Automated Test Suites across All Services
```bash
# 1. Deception Runtime Unit, DSG, Strategy & Isolation Tests
cd deception && npm test

# 2. Detection Service Pytest Suite
PYTHONPATH=detection ./detection/.venv/bin/pytest detection/tests/test_detection.py

# 3. Gateway Unit, Integration, Shadow Mode & Security Tests
cd gateway && npm test

# 4. Backend Unit & Health Tests
cd backend && npm test

# 5. Frontend Production Build Verification
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
| `MAX_REQUEST_BODY_SIZE` | Maximum permitted request body size in bytes | `1048576` (1MB) | Gateway/Deception |
| `DETECTION_SERVICE_URL` | Internal URL of ML detection engine | `http://detection:8000` | Gateway |
| `DETECTION_TIMEOUT_MS` | Detection request timeout before fail-open | `500` | Gateway |
| `DETECTION_ENABLED` | Enable or disable ML detection inspection | `true` | Gateway |
| `DETECTION_PORT` | Python FastAPI detection service port | `8000` | Detection |
| `DECEPTION_PORT` | Deception runtime HTTP listening port | `5050` | Deception |
| `DECEPTION_SERVICE_URL`| Internal URL of Deception runtime | `http://deception:5050` | Deception |
| `SESSION_TTL_MS` | Deception session sliding TTL in ms | `1800000` (30m) | Deception |
| `MAX_SESSIONS` | Maximum in-memory concurrent sessions | `1000` | Deception |
| `PORT` | Backend HTTP listening port | `4000` | Backend |
| `HOST` | Bind host address | `0.0.0.0` | Gateway/Backend/Detection/Deception |
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

## 7. Next Stage: Stage 5 Preview

- **Stage 5: Dynamic Traffic Diversion, Dashboard & Telemetry**
  - Gateway active policy diversion: route confirmed malicious sessions (`risk_score >= threshold`) from genuine backend into isolated `deception/` runtime.
  - Interactive attack graph & session replay in `frontend/`.
  - SIEM telemetry pipeline: stream sanitized deception audit logs to backend for threat intelligence analytics.
