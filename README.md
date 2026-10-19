# AI-Enabled Adaptive Cyber Deception Gateway for Real-Time Attacker Detection

> **Current Status: Stage 12 — Research Literature Review and Patent Prior-Art Investigation**

A modular, adaptive cyber deception platform that identifies malicious network traffic using machine learning, diverts adversaries into isolated, high-interaction honeypots in real time, and defends operational infrastructure with multi-tenant isolation, cryptographic DNS TXT verification, role-based access control, zero-leak deception quarantine policies, a unified security event pipeline, an audited research benchmark framework, and rigorous adversarial robustness & architectural ablation validation.

---

## 1. Project Structure

```
.
├── gateway/               # [Stage 2, 3, 5, 6, 8 — Active] Reverse proxy, ML scoring, policy controller, metrics & events
│   ├── src/               # Code (app.ts, proxy.ts, auth.ts, controller.ts, sessionRouter.ts, metrics.ts, eventRecorder.ts, des.ts, features.ts)
│   ├── test-origin/       # Authorized internal test origin (unexposed to host)
│   ├── Dockerfile         # Multi-stage container build
│   └── package.json       # Dependencies & test scripts (70 unit, controller, RBAC & Stage 8 tests)
├── detection/             # [Stage 3, 9, 10, 11 — Active] Python FastAPI ML anomaly detection service
│   ├── src/               # Code (main.py, schemas.py, deterministic.py, ml_model.py, dataset.py)
│   ├── tests/             # Pytest test suite (37 tests: detection, benchmark audit, robustness, routing, provenance)
│   ├── train.py           # Reproducible model training pipeline
│   ├── model.joblib       # Serialized StandardScaler + RandomForest pipeline
│   ├── requirements.txt   # Python dependencies
│   ├── Dockerfile         # Python 3.11 container build
│   └── README.md          # Model specifications, feature schema & synthetic data limitations
├── deception/             # [Stage 4-6 — Active] Isolated dynamic deception runtime & DSG
│   ├── src/               # Code (app.ts, dsg.ts, policy.ts, sessionStore.ts, strategy.ts, syntheticData.ts)
│   ├── Dockerfile         # Multi-stage container build with unprivileged node user
│   └── package.json       # Dependencies & test scripts (18 tests)
├── backend/               # [Stage 1, 6, 7, 8 — Active] Multi-tenant orgs, app onboarding, DNS TXT verification, event pipeline & RBAC
│   ├── src/               # Application code (app.ts, auth.ts, orgAuth.ts, originValidation.ts, domainVerification.ts, db.ts, config.ts, routes/)
│   ├── Dockerfile         # Multi-stage container build
│   └── package.json       # Dependencies & test scripts (32 tests)
├── frontend/              # [Stage 1-8 — Active] React Vite console with multi-tenant workspace, app onboarding, events pipeline & metrics
│   ├── src/               # React components (App.jsx, main.jsx, index.css)
│   ├── Dockerfile         # Container build with lightweight static server
│   └── vite.config.js     # Vite configuration
├── research/              # [Stage 12 — Active] Scholarly literature review, patent prior-art matrix & research gap
│   ├── literature_review.md              # State-of-the-art review across 10 canonical scholarly sources
│   ├── patent_prior_art_matrix.md        # Deep-dive patent claim mapping and disclosure timeline
│   ├── research_gap_and_contributions.md # Defensible research gap, contributions & hypotheses
│   └── source_register.json              # Machine-readable register of verified literature and patents
├── data/                  # [Stage 9, 10, 11] Versioned benchmark, robustness, and external datasets
│   └── scenarios/         # Standardized datasets with SHA-256 verification
│       ├── benchmark_scenarios_v1.json   # 120 scenarios (60 Dev + 60 Held-Out Test)
│       ├── robustness_scenarios_v1.json  # 70 scenarios (false positive probes, evasions, unseen templates)
│       ├── external_benchmark_v1.json    # 100 scenarios (CSIC 2010 + OWASP CRS + Project controls)
│       └── external_benchmark_v1_provenance.json # 1-to-1 provenance metadata and legal terms mapping
├── scripts/               # [Stage 8-11] Generators and empirical evaluation runners
│   ├── generate_scenarios.py             # 120-scenario benchmark generator
│   ├── generate_robustness_scenarios.py  # 70-scenario adversarial robustness generator
│   ├── generate_provenance_metadata.py   # Machine-readable provenance generator
│   ├── evaluation_runner.py              # Comparative benchmark, ablation & robustness evaluation runner
│   └── run_external_evaluation.py        # External benchmark runner
├── reports/               # [Stage 8-11] Reproducibility records and empirical research reports
│   ├── evaluation_results.json           # 120-scenario baseline comparison results
│   ├── ablation_and_robustness_results.json # Full multi-variant ablation & robustness outcomes
│   ├── robustness_and_ablation_study.md  # Comprehensive Stage 10 empirical research report
│   ├── external_benchmark_results.json   # External benchmark empirical results
│   └── external_benchmark_evaluation.md  # Comprehensive Stage 11 external research report
├── infra/                 # Docker Compose & local infrastructure configuration
├── docs/                  # Architecture specifications and documentation
│   └── architecture.md    # System architecture, trust boundaries, DES math, benchmark & ablation analysis
├── docker-compose.yml     # Local multi-service orchestration (7 services, dual bridge networks, isolated deception)
├── .env.example           # Environment template with Stage 8/9/10 variables
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

4. **Emergency Killswitch (Requires Operator Authentication):**
Privileged endpoints require an authenticated administrator token:
```bash
# Obtain Admin JWT token
ADMIN_TOKEN=$(curl -s -X POST http://localhost:4000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"YourAdminPassword123!"}' | jq -r .token)

# Force all traffic to legitimate origin:
curl -X POST http://localhost:8080/api/gateway/emergency-disable \
  -H "Authorization: Bearer $ADMIN_TOKEN"

# Verify traffic routes to origin:
curl -i -H "X-Session-ID: attacker-session-01" "http://localhost:8080/api/admin"
# Returns: X-Routing-Decision: ORIGIN, X-Routing-Reason: EMERGENCY_DISABLE_ACTIVE

# Re-enable active diversion:
curl -X POST http://localhost:8080/api/gateway/emergency-enable \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

### 5.4 Stage 6 Operator Authentication & RBAC

1. **Register Operator Account:**
```bash
# Register an administrator account
curl -s -X POST http://localhost:4000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"sec_admin","password":"ComplexPassword123!","email":"admin@cyberdeception.local","role":"admin"}' | jq

# Register a read-only analyst account
curl -s -X POST http://localhost:4000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"sec_analyst","password":"ComplexPassword123!","email":"analyst@cyberdeception.local","role":"analyst"}' | jq
```

2. **Login and Role Enforcement:**
```bash
# Login as Analyst
ANALYST_TOKEN=$(curl -s -X POST http://localhost:4000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"sec_analyst","password":"ComplexPassword123!"}' | jq -r .token)

# Attempt privileged operation (Fails with 403 Forbidden)
curl -s -X POST http://localhost:8080/api/gateway/emergency-disable \
  -H "Authorization: Bearer $ANALYST_TOKEN" | jq
# Returns: {"error":"Forbidden","message":"Insufficient permissions...","requiredPermission":"routing:control"}
```

3. **Zero-Leak Deception Failure Quarantine:**
When a session is classified as malicious and assigned to deception, any runtime failure returns HTTP 503 Quarantined to prevent the attacker from ever reaching the real origin:
```bash
curl -i -H "X-Session-ID: trapped-attacker-session" "http://localhost:8080/api/admin"
# Returns on failure:
# HTTP/1.1 503 Service Unavailable
# X-Routing-Fallback: quarantined
# X-Routing-Decision: DECEPTION
# X-Routing-Reason: DECEPTION_UNAVAILABLE_QUARANTINED
```

### 5.5 Stage 7 Multi-Tenant Onboarding & DNS TXT Verification Walkthrough

```bash
# 1. Login to obtain JWT Bearer Token
TOKEN=$(curl -s -X POST http://localhost:4000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"sec_admin","password":"SuperSecretAdminPassword123!"}' | jq -r .token)

# 2. Create Organisation Workspace
ORG_ID=$(curl -s -X POST http://localhost:4000/api/orgs \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"Acme Cyber Corp","slug":"acme-corp","description":"Enterprise Tenant"}' | jq -r .organisation.id)

# 3. Register Application with Approved Domain & Origin
# (Returns unverified status and cryptographic DNS TXT challenge: _deception-challenge.<domain>)
APP_ID=$(curl -s -X POST http://localhost:4000/api/orgs/$ORG_ID/apps \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "displayName": "Acme Customer Portal",
    "environment": "production",
    "approvedDomain": "portal.acme.com",
    "configuredOrigin": "http://test-origin:5000"
  }' | jq -r .application.id)

# 4. Attempt Interception Activation while Unverified (Enforces Safety Invariant: HTTP 400 Rejected)
curl -i -X POST http://localhost:4000/api/orgs/$ORG_ID/apps/$APP_ID/activate \
  -H "Authorization: Bearer $TOKEN"
# HTTP/1.1 400 Bad Request
# {"error":"Bad Request","message":"Cannot activate unverified application (domain is not verified)..."}

# 5. Execute Server-Side DNS TXT Check to Verify Domain Ownership
curl -s -X POST http://localhost:4000/api/orgs/$ORG_ID/apps/$APP_ID/verify \
  -H "Authorization: Bearer $TOKEN"

# 6. Retrieve Tenant-Scoped Audit Event Trail
curl -s http://localhost:4000/api/orgs/$ORG_ID/audit \
  -H "Authorization: Bearer $TOKEN" | jq .auditEvents
```

### 5.6 Stage 8 Security Events Pipeline, Metrics & Research Evaluation Walkthrough

```bash
# 1. Inspect Live Gateway Percentile Latency & Telemetry Metrics
curl -s http://localhost:8080/api/gateway/metrics | jq .

# 2. Query Unified Security Events Pipeline for an Organisation (Tenant Scoped)
curl -s http://localhost:4000/api/orgs/$ORG_ID/events?limit=10 \
  -H "Authorization: Bearer $TOKEN" | jq .

# 3. Retrieve Aggregated Security Event Metrics & Deception Summary
curl -s http://localhost:4000/api/orgs/$ORG_ID/events/summary \
  -H "Authorization: Bearer $TOKEN" | jq .

# 4. Execute the Standalone Research Evaluation Runner (120 Synthetic Benchmark Requests)
# Compares B1 (Direct), B2 (Static Honeypot), B3 (Rule-Based Heuristic), and B4 (Proposed ML+DSG)
python3 scripts/evaluation_runner.py

# 5. Inspect Generated Evaluation Results Artifact
cat reports/evaluation_results.json | jq .
```

### 5.7 Automated Test Suites across All Services (157 Tests Total)
```bash
# 1. Gateway Unit, Decision Controller, Session Routing, Operator RBAC, Stage 8 Events & Stage 11 Routing Tests (70 tests)
cd gateway && npm test

# 2. Backend Health, Operator Auth, Multi-Tenant Models, DNS TXT, Stage 8 Event Pipeline & SSRF Tests (32 tests)
cd backend && npm test

# 3. Deception Runtime Unit, DSG, Strategy & Isolation Tests (18 tests)
cd deception && npm test

# 4. Detection Pytest Suite: Benchmark, Ablation, Routing Semantics, Provenance & Terms Tests (37 tests)
cd detection && .venv/bin/pytest

# 5. Independent Research Benchmark & Ablation Study Runner
python3 scripts/evaluation_runner.py

# 6. External Public HTTP Benchmark Evaluation Runner (CSIC 2010 & OWASP CRS)
python3 scripts/run_external_evaluation.py

# 7. Frontend Production Build Verification
cd frontend && npm run build
```

### 5.8 Stage 9 & 10 Empirical Research Benchmark & Ablation Study Results
The evaluation framework evaluates 4 baseline architectures and 4 architectural ablation variants across two versioned datasets:
1. **Benchmark v1.0.0 (120 samples):** Standard attacks & benign traffic (`data/scenarios/benchmark_scenarios_v1.json`).
2. **Adversarial Robustness v1.0.0 (70 samples):** False positive probes, double-encoded evasions, and unseen injection templates (`data/scenarios/robustness_scenarios_v1.json`).

#### Multi-Variant Ablation Comparison (Held-Out Test vs. Adversarial Robustness):

| Variant | Architecture | Test F1 | Test Acc | Test Recall | Origin Leaks | Test DES | Robustness Acc | Robustness FPR | Robustness FNR | p50 Gateway Latency |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Variant A (B4)** | Full System (ML + Rules + Adaptive DSG + Sticky) | **1.000** | **100.0%** | **100.0%** | **0 (0.0%)** | **0.925** | 54.3% | 40.5% | 51.5% | 13.580 ms |
| **Variant B** | No-ML Ablation (Rules-Only Policy) | 0.909 | 91.7% | 83.3% | 5 (16.7%) | 0.000 | **71.4%** | **8.1%** | 51.5% | **0.015 ms** |
| **Variant C** | No-Adaptation Ablation (Flat Decoy Mock) | 1.000 | 100.0% | 100.0% | 0 (0.0%) | **0.662** | 54.3% | 40.5% | 51.5% | 13.533 ms |
| **Variant D** | No-Behavioral-History (Stateless Routing) | 0.889 | 90.0% | 80.0% | 6 (20.0%) | 0.000 | 55.7% | 37.8% | 51.5% | 13.614 ms |

### 5.9 Stage 11 External Public HTTP Benchmark Evaluation Results (CSIC 2010 & OWASP CRS)
Evaluated against 100 standardized synthetic HTTP requests from the published CSIC 2010 HTTP testbed dataset and OWASP CRS benchmark (`data/scenarios/external_benchmark_v1.json`, Content SHA-256: `f11d6894b9b5d486785008f2062d88d19263e2330971dae07bd96813741940c3`):

| Configuration | Architecture | Precision | Recall (Containment) | F1 Score | Accuracy | Origin Leaks (FNR) | False Positives (FPR) | p50 Latency |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **B1: Direct Passthrough** | Reverse Proxy (No Sec) | 0.0% | 0.0% | 0.000 | 50.0% | 50/50 (100.0%) | 0/50 (0.0%) | 0.2 µs |
| **B2: Static Heuristic** | Substring Matching | 100.0% | 6.0% | 0.113 | 53.0% | 47/50 (94.0%) | 0/50 (0.0%) | 0.4 µs |
| **B3: Rule-Based Adaptive**| Regex Heuristics | 100.0% | 46.0% | 0.630 | 73.0% | 27/50 (54.0%) | 0/50 (0.0%) | 0.003 ms |
| **B4: Proposed Gateway (A)**| Full Proposed ML+DSG | **100.0%** | **74.0%** | **0.851** | **87.0%** | **13/50 (26.0%)** | **0/50 (0.0%)** | 13.650 ms |
| **Variant B (Rules Only)** | Rules Only (No ML) | 100.0% | 46.0% | 0.630 | 73.0% | 27/50 (54.0%) | 0/50 (0.0%) | **0.016 ms** |

*All results generated dynamically by `python3 scripts/run_external_evaluation.py` with artifacts saved in `reports/external_benchmark_results.json` and documented in `reports/external_benchmark_evaluation.md`.*

### 5.10 Stage 11.1 Dataset & Model Provenance Integrity Audit
- **Artifact Digests Reconciliation:**
  - `data/scenarios/benchmark_scenarios_v1.json`: Raw File SHA-256 = `2ecae8b3eb25342470dc803b04506b007f9a59501b0c98a404603c402842f1fc`, Content SHA-256 = `958fa723ca691d9fbbd6cdc885cbc8509e80e4332bc4e9313ca98e7e2c0a0746` (Unchanged since Stage 9 commit `757f598`).
  - `data/scenarios/robustness_scenarios_v1.json`: Raw File SHA-256 = `7dde7ba551ec2d2e8565169fc23f71c3413f42812cf842f4e638e1b9b9bcf99d`, Content SHA-256 = `03a7cb3aa97dcf6f459b5029c7c5bc9483c840abe24d108282459f8ef71e6e08` (Unchanged since Stage 10 commit `b63ba15`).
  - `detection/model.joblib`: Raw Binary SHA-256 = `4d76bac3bdd82425f8d760aa8437f0eece55c02b82b41614844251292d4fb406` (Frozen artifact since Stage 9 commit `757f598`).
  - `data/scenarios/external_benchmark_v1.json`: Raw File SHA-256 = `b4dc4cb593b17f940eaa1b274903ec50ccf910b8e4c55a135ec0e2507fbb33bc`, Content SHA-256 = `f11d6894b9b5d486785008f2062d88d19263e2330971dae07bd96813741940c3`.
- **CSIC 2010 Provenance:** Generated in a controlled testbed against an e-commerce web application ("tienda1") using automated web vulnerability scanners and crawlers. Documented as automated testbed HTTP traffic, not captured real-world production attack traces.
- **Label Isolation Invariance:** Verified that features and inference results are strictly invariant to ground-truth tampering or removal.

### 5.11 Stage 11.2 External Dataset Citation, Usage-Terms & Provenance Mapping
- **Verified Sources and Citations:**
  - **CSIC 2010:** Information Security Institute (ISI), CSIC (Spanish National Research Council). Authors: C. Torrano-Giménez, A. Pérez-Villegas, G. Álvarez Marañón (2010). Canonical URL: `http://www.isi.csic.es/dataset/`. Primary paper: *Journal of Information Assurance and Security*, 5(4), 446–454.
  - **OWASP CRS:** OWASP ModSecurity Core Rule Set Project (2020–2024). Repository: `https://github.com/coreruleset/coreruleset`. Licensed under Apache 2.0.
- **Independent Usage Terms & Redistribution Rights:**
  - **Local Research Evaluation:** Fully authorized for local execution and benchmark replication across both datasets under academic research fair use and Apache 2.0.
  - **Redistribution Rights:** OWASP CRS permits modification and redistribution with attribution under Apache 2.0. CSIC 2010 was distributed freely for academic research without a formal OSI or Creative Commons license; standalone commercial redistribution or re-licensing carries legal ambiguity and is restricted.
- **Machine-Readable Metadata:** Complete 1-to-1 scenario mapping for all 100 benchmark items published at `data/scenarios/external_benchmark_v1_provenance.json`.

### 5.12 Stage 11.3 Source-to-Scenario Provenance & Rights Verification
- **3-Way Origin Taxonomy & Attribution:**
  - **CSIC 2010 (69 scenarios: 35 Benign, 34 Attacks):** Verbatim requests from CSIC 2010 `normalTrafficTest.txt` and `anomalousTrafficTest.txt` targeting `tienda1`. Includes `EXT-BEN-050` (verified authentic CSIC 2010 e-commerce request `confirmacion.jsp`).
  - **OWASP CRS (16 scenarios: 0 Benign, 16 Attacks):** Derived from OWASP ModSecurity Core Rule Set regression tests (rules 913100, 930100, 932100, 941100, 942100), adapted into REST parameters and JSON schemas.
  - **Project-Created Benign Baseline Controls (15 scenarios: 15 Benign, 0 Attacks):** Scenarios `EXT-BEN-035` through `EXT-BEN-049` were authored directly by the project in Stage 11 to benchmark modern REST API paths (`/api/v1/products`, `/api/v1/health`, etc.) alongside 2010 JSP routes. *Attribution Correction:* Previously misattributed in metadata to "OWASP Web Controls", these are explicitly classified as project-created controls.
- **Corrected Licensing & Legal Terms:**
  - **CSIC 2010:** Original publisher website (`isi.csic.es` / `tic.itefi.csic.es`) published the dataset for research without a formal open-source license. Third-party catalogue tags (e.g. Kaggle/UNB "Public" or "Academic") are portal classifications, not formal legal grants from CSIC. Local research evaluation is standard academic fair use; commercial redistribution rights remain **unresolved and legally ambiguous**, recommending permission or dataset replacement prior to commercial bundling.
  - **OWASP CRS:** Licensed under Apache-2.0 (`v3.3.x / v4.0.0`). The ASL 2.0 license applies **strictly to the 16 CRS-derived attack payloads** and does **not** extend to CSIC 2010 records or project-created controls.
- **Preserved Cryptographic Invariance:**
  - `benchmark_scenarios_v1.json`: `2ecae8b3eb25342470dc803b04506b007f9a59501b0c98a404603c402842f1fc`
  - `robustness_scenarios_v1.json`: `7dde7ba551ec2d2e8565169fc23f71c3413f42812cf842f4e638e1b9b9bcf99d`
  - `external_benchmark_v1.json`: `b4dc4cb593b17f940eaa1b274903ec50ccf910b8e4c55a135ec0e2507fbb33bc` (Content SHA-256: `f11d6894b9b5d486785008f2062d88d19263e2330971dae07bd96813741940c3`)
  - `detection/model.joblib`: `4d76bac3bdd82425f8d760aa8437f0eece55c02b82b41614844251292d4fb406`

### 5.13 Stage 12 Research Literature Review and Patent Prior-Art Investigation
- **Traceable Scholarly Literature Review (`research/literature_review.md`):**
  - Synthesized 10 canonical peer-reviewed publications across 6 core thematic domains: Selective Honeytoken Diversion (*Anagnostakis et al., 2005*), HTTP Anomaly Detection (*Kruegel & Vigna, 2003*; *Torrano-Giménez et al., 2010*), Game-Theoretic Cyber Deception (*Pawlick et al., 2019*; *Sengupta et al., 2020*), Empirical Dwell-Time Metrics (*Ferguson-Walter et al., 2021*; *Han et al., 2018*), Moving Target Defense & Dynamic Shuffling (*Cho et al., 2020*), and Web Honeypots / Sandboxes (*Vetterl & Clayton, 2019*; *Robertson et al., 2006*).
  - Constructed an 8-dimensional scholarly comparison matrix evaluating OSI layer, inspection granularity, redirection triggers, routing statefulness, decoy realism, containment enforcement, evaluation benchmarks, and reported metrics.
- **Preliminary Patent Prior-Art Matrix (`research/patent_prior_art_matrix.md`):**
  - Mapped 8 granted patent assets and published applications across Acalvio, Attivo Networks / SentinelOne, Illusive Networks / Proofpoint, TrapX, NSA, and Argonne: `US10193924B2`, `US9979750B2`, `US10348763B2`, `US10375110B2`, `US10333977B1`, `US11934948B2`, `US20170134423A1`, and `US11876833B2`.
  - Formulated a 7-element technical claim mapping matrix. Identified high prior-art density in dynamic honeypot diversion and threat scoring, establishing that the gateway's novel differentiator lies in the synergistic combination of L7 session-cookie affinity, 4-node DSG finite state automata, and a binary zero-leak gated metric ($\mathbb{I}[L_{\text{leak}} = 0]$).
- **Public Disclosure Timeline & Jurisdictional Novelty Impact:**
  - Audited Git commit history identifying the earliest public disclosure commit on **October 17, 2026, 22:40:18 +0530** (`5520d59`).
  - Evaluated jurisdictional impacts: India (absolute novelty under Sections 29–34 compromised; Section 3(k) computer program bar), United States (35 U.S.C. 102(b)(1) 1-year inventor grace period expiring October 17, 2027; 35 U.S.C. 103 obviousness risks), and Europe (Article 54 EPC absolute novelty bar).
  - Formulated 5 advisory consultation questions for registered patent counsel and recommended defensive open-source publication.
- **Defensible Research Gap & Empirical Contributions (`research/research_gap_and_contributions.md`):**
  - Defined the core research gap across semantic diversion failure, state fragmentation, containment leakage under failure, and metric gaming in literature.
  - Formulated 6 defensible technical contributions, 3 research questions ($RQ_1, RQ_2, RQ_3$), and confirmed empirical hypotheses ($H_1, H_2, H_3$).
  - Explicitly separated verified empirical achievements (100% held-out test recall, 74.0% external benchmark recall with 26.0% origin leakage, 13.62 ms median latency) from unproven claims (live enterprise generalization, real human attacker dwell time, adversarial evasion robustness under unseen attacks).
- **Machine-Readable Provenance Register (`research/source_register.json`):**
  - Fully cataloged DOIs, patent document numbers, assignees, URLs, and publication metadata for all 18 analyzed works.

---

## 6. Environment Variables

| Variable | Description | Default | Service |
|---|---|---|---|
| `GATEWAY_PORT` | Gateway HTTP listening port | `8080` | Gateway |
| `ORIGIN_URL` | Upstream target origin URL | `http://test-origin:5000` | Gateway |
| `ALLOWED_ORIGINS` | Whitelist of approved origins | `http://test-origin:5000,http://deception:5050` | Gateway |
| `ROUTING_MODE` | Routing mode (`shadow` [default] or `active`) | `shadow` | Gateway |
| `EMERGENCY_DISABLE_DIVERSION` | Immediate killswitch to force all traffic to origin | `false` | Gateway |
| `DECEPTION_SERVICE_URL`| Internal URL of Deception runtime | `http://deception:5050` | Gateway/Deception |
| `DECEPTION_SCORE_THRESHOLD` | Minimum risk score required for diversion | `0.70` | Gateway |
| `DECEPTION_FAILURE_POLICY` | Deception failure mode (`quarantine` [default] or `fallback_origin`) | `quarantine` | Gateway |
| `OPERATOR_JWT_SECRET` | Secret key for signing operator authentication tokens | `deception-gateway-operator-secret-key-32chars-min!` | Gateway/Backend |
| `SERVICE_SHARED_SECRET` | Shared secret for internal gateway-to-backend event pipeline | `deception-internal-service-secret-key-32chars!` | Gateway/Backend |
| `BACKEND_URL` | Internal URL of backend service for event dispatch | `http://backend:4000` | Gateway |
| `BCRYPT_SALT_ROUNDS` | Salt rounds for password hashing | `12` | Backend |
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
| `POSTGRES_PORT` | PostgreSQL internal port (unmapped to host in Stage 6) | `5432` | Database |
| `DATABASE_URL` | Full database connection string | `postgresql://...` | Backend/DB |

> **Security Notice:** Never commit `.env` or production credentials to Git. Use `.env.example` as a template for local overrides.
