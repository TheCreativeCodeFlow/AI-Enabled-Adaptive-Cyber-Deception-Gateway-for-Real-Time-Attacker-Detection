# AI-Enabled Adaptive Cyber Deception Gateway for Real-Time Attacker Detection

> **Current Status: Stage 1 — Repository Foundation & Architecture**

A modular, adaptive cyber deception platform that identifies malicious network traffic using machine learning and diverts adversaries into isolated, high-interaction honeypots in real time.

---

## 1. Project Structure

```
.
├── backend/               # Node.js, Express & TypeScript core service
│   ├── src/               # Application code (app.ts, index.ts, index.test.ts)
│   ├── Dockerfile         # Multi-stage container build
│   └── package.json       # Dependencies & test scripts
├── frontend/              # React with JavaScript and Vite
│   ├── src/               # React components (App.jsx, main.jsx, index.css)
│   ├── Dockerfile         # Container build with lightweight static server
│   ├── vite.config.js     # Vite configuration
│   └── package.json       # Dependencies & build scripts
├── gateway/               # [Reserved — Stage 2] Reverse-proxy traffic interception
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
Start all services in detached mode:
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
- `deception-postgres`: `healthy` (port 5432)
- `deception-backend`: `healthy` (port 4000)
- `deception-frontend`: `healthy` (port 3000)

### 3.4 View Logs
```bash
# Follow logs across all services
docker compose logs -f

# Follow specific service logs
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

### Backend (Node.js + Express + TypeScript)
```bash
cd backend

# 1. Install dependencies
npm install

# 2. Run unit & health tests
npm test

# 3. Build TypeScript
npm run build

# 4. Start in development mode (with hot reload)
npm run dev

# Or start compiled production server
npm start
```
- Health Check: `http://localhost:4000/health`
- Root Info: `http://localhost:4000/`

### Frontend (React + Vite)
```bash
cd frontend

# 1. Install dependencies
npm install

# 2. Start Vite development server
npm run dev
```
- Web UI: `http://localhost:3000`

---

## 5. Verification & Testing

### 5.1 Backend Health Endpoint
```bash
curl -i http://localhost:4000/health
```
Expected JSON Response (`HTTP 200 OK`):
```json
{
  "status": "healthy",
  "service": "backend",
  "stage": "Stage 1",
  "timestamp": "...",
  "uptime": 12.34
}
```

### 5.2 Frontend Landing Page
Open your browser to:
```
http://localhost:3000
```
Verify that:
1. The landing page renders the Stage 1 title and module status.
2. The Backend Health Status card queries `http://localhost:4000/health` and shows a green `HEALTHY` indicator.

### 5.3 Automated Backend Tests
```bash
cd backend && npm test
```

---

## 6. Environment Variables

| Variable | Description | Default | Service |
|---|---|---|---|
| `PORT` | Backend HTTP listening port | `4000` | Backend |
| `HOST` | Backend bind host address | `0.0.0.0` | Backend |
| `NODE_ENV` | Environment mode (`development`/`production`) | `development` | Backend |
| `CORS_ORIGIN` | Allowed origin for CORS requests | `http://localhost:3000` | Backend |
| `FRONTEND_PORT` | Frontend HTTP listening port | `3000` | Frontend |
| `VITE_BACKEND_URL` | Backend API URL for frontend client | `http://localhost:4000` | Frontend |
| `POSTGRES_USER` | PostgreSQL superuser username | `deception_user` | Database |
| `POSTGRES_PASSWORD`| PostgreSQL superuser password | `deception_pass` | Database |
| `POSTGRES_DB` | PostgreSQL default database | `deception_db` | Database |
| `POSTGRES_PORT` | PostgreSQL external host port | `5432` | Database |
| `DATABASE_URL` | Full database connection string | `postgresql://...` | Backend/DB |

> **Security Notice:** Never commit `.env` or production credentials to Git. Use `.env.example` as a template for local overrides.

---

## 7. Next Stage: Stage 2 Preview

- **Stage 2: Reverse-Proxy Gateway & Traffic Interception (`gateway/`)**
  - Implement reverse-proxy traffic interceptor.
  - Request inspection pipeline & feature extraction.
  - Dynamic routing rules engine.
