# AI-Enabled Adaptive Cyber Deception Gateway for Real-Time Attacker Detection

> **Current Status: Stage 5 — Policy-Controlled Traffic Diversion**

A modular, adaptive cyber deception platform that identifies malicious network traffic using machine learning and diverts adversaries into isolated, high-interaction honeypots in real time.

---

## 1. Project Structure

```
.
├── gateway/               # [Stage 2, 3, 5 — Active] Reverse proxy, ML scoring & policy routing controller
│   ├── src/               # Code (app.ts, proxy.ts, controller.ts, sessionRouter.ts, detector.ts, features.ts, config.ts, logger.ts)
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
├── deception/             # [Stage 4-5 — Active] Isolated dynamic deception runtime & DSG
│   ├── src/               # Code (app.ts, dsg.ts, policy.ts, sessionStore.ts, strategy.ts, syntheticData.ts)
│   ├── Dockerfile         # Multi-stage container build with unprivileged node user
│   ├── package.json       # Dependencies & test scripts
│   └── README.md          # DSG specifications, layer models & API contracts
├── backend/               # [Stage 1 — Active] Node.js, Express & TypeScript core service
│   ├── src/               # Application code (app.ts, index.ts, index.test.ts)
│   ├── Dockerfile         # Multi-stage container build
│   └── package.json       # Dependencies & test scripts
├── frontend/              # [Stage 1-5 — Active] React with JavaScript and Vite operator console
│   ├── src/               # React components (App.jsx, main.jsx, index.css)
│   ├── Dockerfile         # Container build with lightweight static server
│   ├── vite.config.js     # Vite configuration
│   └── package.json       # Dependencies & build scripts
├── infra/                 # Docker Compose & local infrastructure configuration
├── docs/                  # Architecture specifications and documentation
│   └── architecture.md    # System architecture, trust boundaries & roadmap
├── docker-compose.yml     # Local multi-service orchestration (7 services, dual bridge networks)
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
- `deception-detection`: `healthy` (internal port `8000`, internal network)
- `deception-runtime`: `healthy` (internal port `5050`, isolated network)
- `deception-test-origin`: `healthy` (internal port `5000`, internal network)
- `deception-backend`: `healthy` (published host port `4000`)
- `deception-frontend`: `healthy` (published host port `3000`)
- `deception-postgres`: `healthy` (published host port `5432`)

### 3.4 View Logs
```bash
# Follow logs across all services
docker compose logs -f

# Follow deception runtime logs
docker compose logs -f deception

# Follow gateway logs (includes routing decisions and target origins)
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

### Gateway (Reverse Proxy + Decision Controller)
```bash
cd gateway
npm install
npm test
npm run build
ROUTING_MODE=shadow npm run dev
```
- Health Check: `http://localhost:8080/health`

### Deception Runtime (Isolated DSG Service)
```bash
cd deception
npm install
npm test
npm run build
npm run dev
```
- Health Check: `http://localhost:5050/health`

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

### 5.1 Gateway Health & Routing Status Check
```bash
curl -s http://localhost:8080/health | jq
```
Expected output:
```json
{
  "status": "healthy",
  "service": "gateway",
  "stage": "Stage 5 — Policy-Controlled Traffic Diversion",
  "upstream": "http://test-origin:5000",
  "detectionService": "http://detection:8000",
  "detectionEnabled": true,
  "routingMode": "shadow",
  "emergencyDisableDiversion": false,
  "deceptionService": "http://deception:5050",
  "deceptionThreshold": 0.7,
  "activeDeceptionSessions": 0
}
```

### 5.2 Shadow Mode Verification (Default Safe Invariant)
In shadow mode, high-confidence malicious probes are scored and classified, but the gateway **never** diverts traffic to deception:
```bash
curl -i "http://localhost:8080/api/admin/probe?cmd=eval&union=select"
```
Headers returned:
```http
X-Routing-Decision: ORIGIN
X-Routing-Reason: SHADOW_MODE_ACTIVE
X-Routing-Mode: shadow
X-Origin-ID: authorized-test-origin
```

### 5.3 Active Mode Verification (Policy Diversion)
To enable active policy diversion, set `ROUTING_MODE=active` in `.env` (or via environment variable):
```bash
ROUTING_MODE=active docker compose up -d --force-recreate gateway
```

1. **Benign Request:**
```bash
curl -i http://localhost:8080/api/echo
# Returns: X-Routing-Decision: ORIGIN, X-Routing-Reason: BENIGN_EVALUATION
```

2. **Malicious Probe Diverted to Deception:**
```bash
curl -i -H "X-Session-ID: attacker-session-01" "http://localhost:8080/api/admin"
# Returns:
# X-Routing-Decision: DECEPTION
# X-Routing-Reason: HIGH_CONFIDENCE_MALICIOUS_DIVERT
# X-Deception-Runtime: active
```

3. **Sticky Session Consistency:**
```bash
# Subsequent request with the same session stays in synthetic environment:
curl -i -H "X-Session-ID: attacker-session-01" "http://localhost:8080/api/catalog"
# Returns:
# X-Routing-Decision: DECEPTION
# X-Routing-Reason: STICKY_SESSION_ASSIGNMENT
# X-DSG-Current-Node: catalog
```

4. **Emergency Killswitch:**
```bash
# Immediately force all traffic to legitimate origin:
curl -X POST http://localhost:8080/api/gateway/emergency-disable

# Verify traffic routes to origin:
curl -i -H "X-Session-ID: attacker-session-01" "http://localhost:8080/api/admin"
# Returns: X-Routing-Decision: ORIGIN, X-Routing-Reason: EMERGENCY_DISABLE_ACTIVE

# Re-enable:
curl -X POST http://localhost:8080/api/gateway/emergency-enable
```

### 5.4 Automated Test Suites across All Services
```bash
# 1. Gateway Unit, Decision Controller, Session Routing & Integration Tests (29 tests)
cd gateway && npm test

# 2. Deception Runtime Unit, DSG, Strategy & Isolation Tests (18 tests)
cd deception && npm test

# 3. Detection Service Pytest Suite (6 tests)
cd detection && .venv/bin/pytest

# 4. Backend Unit & Health Tests (3 tests)
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
| `ALLOWED_ORIGINS` | Comma-separated whitelist of approved origins | `http://test-origin:5000,http://localhost:5000,http://127.0.0.1:5000,http://deception:5050` | Gateway |
| `ROUTING_MODE` | Routing mode (`shadow` [default] or `active`) | `shadow` | Gateway |
| `EMERGENCY_DISABLE_DIVERSION` | Immediate killswitch to force all traffic to origin | `false` | Gateway |
| `DECEPTION_SERVICE_URL`| Internal URL of Deception runtime | `http://deception:5050` | Gateway/Deception |
| `DECEPTION_SCORE_THRESHOLD` | Minimum risk score required for diversion | `0.70` | Gateway |
| `PROXY_TIMEOUT_MS` | Proxy request timeout in milliseconds | `5000` | Gateway |
| `MAX_REQUEST_BODY_SIZE` | Maximum permitted request body size in bytes | `1048576` (1MB) | Gateway/Deception |
| `DETECTION_SERVICE_URL` | Internal URL of ML detection engine | `http://detection:8000` | Gateway |
| `DETECTION_TIMEOUT_MS` | Detection request timeout before fail-open | `500` | Gateway |
| `DETECTION_ENABLED` | Enable or disable ML detection inspection | `true` | Gateway |
| `DETECTION_PORT` | Python FastAPI detection service port | `8000` | Detection |
| `DECEPTION_PORT` | Deception runtime HTTP listening port | `5050` | Deception |
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
