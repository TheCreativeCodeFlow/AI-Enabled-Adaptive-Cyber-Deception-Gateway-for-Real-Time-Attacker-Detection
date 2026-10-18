# Architecture Specification: AI-Enabled Adaptive Cyber Deception Gateway

## 1. System Overview

The **AI-Enabled Adaptive Cyber Deception Gateway** is a defensive cyber security platform designed to detect, mislead, and analyze adversaries in real time. Rather than simply blocking malicious traffic, the gateway uses machine learning to classify incoming session behavior and selectively diverts malicious actors into an isolated, high-interaction deception runtime (honeypots, decoy services, synthetic data). This exhausts attacker resources, collects high-fidelity threat intelligence, and prevents unauthorized access to genuine core assets without alerting the adversary.

---

## 2. High-Level System Architecture

```mermaid
flowchart TD
    subgraph UntrustedZone["Untrusted Network (External)"]
        Client[Incoming Client Traffic]
    end

    subgraph DMZ["DMZ / Ingress Layer"]
        Gateway[Gateway Service<br/>Reverse-Proxy & Traffic Interceptor<br/><i>gateway/ - Stage 2</i>]
    end

    subgraph CoreZone["Core Application Zone"]
        Backend[Backend Core API<br/>Node.js / Express / TypeScript<br/><i>backend/ - Stage 1</i>]
        Frontend[Operator Dashboard & UI<br/>React / Vite<br/><i>frontend/ - Stage 1</i>]
        DB[(PostgreSQL Database<br/>Events & Telemetry<br/><i>infra/ - Stage 1</i>)]
    end

    subgraph MLZone["Machine Learning Zone"]
        MLService[Detection Service<br/>Python ML Anomaly Engine<br/><i>detection/ - Stage 3</i>]
    end

    subgraph DeceptionZone["Isolated Deception Zone (Containment)"]
        DecoyEnv[Deception Runtime & DSG<br/>Stateful Honeypots & Decoy Services<br/><i>deception/ - Stage 4</i>]
    end

    Client -->|HTTP/HTTPS| Gateway
    Gateway -->|Feature Stream & Telemetry (Shadow Mode)| MLService
    MLService -->|Threat Score & Classification| Gateway

    Gateway -->|Benign Traffic Routing| Backend
    Gateway -.->|Verified Runtime (Diversion Deferred)| DecoyEnv

    Frontend -->|Admin & Status Queries| Backend
    Backend -->|Read/Write State| DB
    DecoyEnv -.->|Sanitized Audit Logs| Backend

    classDef active fill:#1b5e20,stroke:#4caf50,color:#fff;
    classDef planned fill:#424242,stroke:#9e9e9e,color:#fff,stroke-dasharray: 5 5;
    class Backend,Frontend,DB,Gateway,MLService,DecoyEnv active;
```

---

## 3. Service Responsibilities

### 3.1 `frontend/` (Stage 1 — Active)
- **Tech Stack:** React, JavaScript, Vite.
- **Role:** Web operator interface for monitoring system health, reviewing threat intelligence, and configuring gateway policies.
- **Stage 1 Scope:** Minimal landing page displaying live backend connection status, module readiness status, and system metadata.

### 3.2 `backend/` (Stage 1 — Active)
- **Tech Stack:** Node.js, Express, TypeScript.
- **Role:** Central control plane, API provider, and telemetry coordinator.
- **Stage 1 Scope:** Health check service (`GET /health`), CORS support, structured graceful shutdown, and containerized deployment.

### 3.3 `gateway/` (Stage 2 & Stage 3 — Active)
- **Tech Stack:** Node.js, Express, TypeScript reverse proxy.
- **Role:** Primary perimeter traffic ingress. Intercepts HTTP/S requests, normalizes paths, strictly validates upstream whitelisting (preventing SSRF and open proxy), enforces body size limits, handles timeouts, attaches request IDs (`X-Request-ID`), preserves response headers/cookies, and outputs structured zero-leakage logs.
- **Stage 3 Integration:** Extracts security-relevant request metadata (path entropy, depth, query tokens, request rate, header anomalies, body size) without transmitting raw bodies, cookies, or auth tokens. Queries the internal detection engine in **Shadow Mode** with strict timeouts (fail-open resilience). Replaces/strips any client-provided `X-Detection-*` spoofed headers and forwards all traffic faithfully to authorized upstream.

### 3.4 `detection/` (Stage 3 — Active)
- **Tech Stack:** Python 3.11/3.14, FastAPI, Pydantic, Scikit-learn (RandomForestClassifier + StandardScaler), Uvicorn.
- **Role:** Real-time ML inference and behavioral risk scoring service (`POST /score`, `GET /health`).
- **Stage 3 Scope:**
  - Pydantic v2 data validation schemas (`RequestFeatures`, `DetectionResult`).
  - Deterministic explainable heuristic engine evaluating weighted multi-factor indicators (suspicious paths, SQLi/traversal keywords, frequency anomalies, high entropy).
  - Scikit-learn anomaly classifier trained on reproducible synthetic attack and benign distributions (`train.py`, `model.joblib`).
  - Dual-scoring ensemble outputting calibrated risk scores [0.0, 1.0], classification labels (`BENIGN`, `SUSPICIOUS`, `MALICIOUS`), and structured explainable evidence tags.
  - Zero host exposure; communicates exclusively across internal Docker bridge networks.

### 3.5 `deception/` (Stage 4 — Active)
- **Tech Stack:** Node.js, Express, TypeScript.
- **Role:** Isolated, stateful active cyber deception runtime and Deception State Graph (DSG).
- **Stage 4 Scope:**
  - Deception State Graph (DSG) with validated nodes (`entrypoint`, `catalog`, `users`, `files`, `admin`, `auth`) and strict transition boundaries.
  - Three-tier state architecture:
    1. *Protected Policy Layer:* Frozen, immutable safety constraints and operation allowlists.
    2. *Controlled Dynamic Layer:* Session-specific cloned synthetic records (users, files, services, decoy injection).
    3. *Observation Layer:* Pseudonymous session identifiers, visited nodes, telemetry timestamps, and interaction history.
  - Deterministic Deception Strategy Selector with policy assertion (`ADD_SYNTHETIC_DECOY_RECORD`, `EXPOSE_SYNTHETIC_SERVICE`, `INCREASE_OBSERVATION_DETAIL`, `MAINTAIN_CURRENT_STATE`, `DISABLE_DECEPTION`).
  - Synthetic APIs (`/api/catalog`, `/api/users`, `/api/files`, `/api/admin`, `/api/auth/login`) with zero access to real databases, host files, or real credentials.
  - Strictly containerized on internal Docker network (`deception-network`, port `5050`) with no published host port, unprivileged user `node`, sliding TTL session expiration, and LRU memory capacity controls.

### 3.6 `infra/` (Stage 1 — Active)
- **Tech Stack:** Docker, Docker Compose, PostgreSQL 16.
- **Role:** Declarative local and staging infrastructure management. Provides reproducible service orchestration and verified healthchecks across all 7 platform services.

---

## 4. Trust Boundaries & Security Model

```
[ External Internet / Untrusted Zone ]
                 │
═════════════════╪═════════════════════════════════════════════════════════
 TRUST BOUNDARY 1: Perimeter Ingress (TLS Termination, Rate Limiting, WAF)
═════════════════╪═════════════════════════════════════════════════════════
                 ▼
       [ Gateway Reverse Proxy ]
        /                     \
       / (Benign)              \ (Malicious / Suspected)
      ▼                         ▼
═════════════════════════   ═══════════════════════════════════════════════
 TRUST BOUNDARY 2: Core      TRUST BOUNDARY 3: Deception Isolation Barrier
 (Internal VPC / Auth)       (Air-gapped Sandbox / Egress Zero-Trust)
═════════════════════════   ═══════════════════════════════════════════════
      │                                 │
      ▼                                 ▼
 [ Backend & Database ]        [ Deception Honeypots & DSG ]
```

1. **Perimeter Boundary (Untrusted to DMZ):** Only the Gateway service exposes public ports. No internal backend services, databases, or deception containers are accessible directly from the public network.
2. **Core Boundary (DMZ to Internal Services):** Backend APIs and ML detection services communicate only with verified internal clients over private Docker bridge networks.
3. **Deception Isolation Boundary (Containment):** The deception runtime is strictly isolated from core production systems. Deception containers have zero outbound network routes to internal subnets or the wider internet to prevent pivot/lateral movement attacks. Egress logging is asynchronous and unidirectionally sanitized.

---

## 5. Request & Data Flows

### 5.1 Benign Traffic Flow (Normal Path)
1. User sends request to Gateway.
2. Gateway extracts security-relevant metadata (zero credentials/bodies).
3. Gateway queries Detection service asynchronously or within bounded timeout (`/score`).
4. Detection service evaluates threat score (`score < threshold`, label `BENIGN`).
5. Gateway attaches correlation and audit metadata and forwards request unchanged to genuine `backend/` or origin service.
6. Upstream processes request and returns response through Gateway to user.

### 5.2 Malicious Traffic Flow (Stage 3 & 4 Shadow Mode vs Stage 5 Active Policy Diversion)
1. Adversary executes scanning, SQL injection, path traversal, or probe requests against Gateway.
2. Gateway extracts derived features and queries Detection service.
3. Detection engine flags malicious patterns (`score >= 0.70`, label `MALICIOUS`) with evidence factors.
4. **Stage 4 (Deception Runtime Verification & Shadow Mode):** The isolated Deception Runtime (`deception/`) is verified and healthy on the internal network. However, **gateway traffic diversion is intentionally inactive** in Stage 4. All gateway traffic continues normal forwarding to the test origin in Shadow Mode.
5. **Stage 5 (Future Dynamic Diversion):** Gateway policy routing will be activated to transparently divert confirmed attacker sessions into `deception/`.

---

## 6. Staged Implementation Plan

| Stage | Focus Area | Deliverables | Current Status |
|---|---|---|---|
| **Stage 1** | **Repository Foundation & Architecture** | Modular directory layout, minimal React frontend, Express TypeScript backend with `GET /health`, Docker Compose orchestration, PostgreSQL healthcheck, architecture documentation. | **Active / Complete** |
| **Stage 2** | **Gateway & Traffic Interception** | Reverse-proxy service in `gateway/`, request inspection pipeline, routing policies, configurable routing rules, isolated test origin. | **Active / Complete** |
| **Stage 3** | **ML Detection Engine & Gateway Integration** | Python FastAPI ML service in `detection/`, feature extraction, dual deterministic + scikit-learn models, shadow mode gateway integration, fail-open resilience. | **Active / Complete** |
| **Stage 4** | **Dynamic Deception Runtime & DSG** | Isolated Node.js/TypeScript deception service in `deception/`, Deception State Graph (DSG), three logical state layers, deterministic strategy selector, session-isolated synthetic APIs. | **Active / Complete** |
| **Stage 5** | **Dynamic Traffic Diversion, Dashboard & Telemetry** | Active gateway routing policy diversion, interactive threat visualization in `frontend/`, attack graph replay, alert notifications, SIEM event export. | *Reserved* |

---

## 7. Current State & Known Limitations (Stage 4)

- **Gateway Diversion Inactive:** The deception runtime is fully operational and tested in isolation on the Docker network, but gateway diversion remains inactive in Stage 4 to preserve strict validation boundaries.
- **In-Memory Session Store:** Deception sessions are maintained in-memory using `InMemorySessionStore` with sliding TTL (30 minutes) and LRU capacity eviction (1,000 sessions). A persistent storage interface (`SessionStore`) is defined to support external databases (e.g., Redis or PostgreSQL) in future stages without architectural changes.
- **Synthetic Data Boundaries:** All synthetic users, files, and services are mocked fixtures. No real credentials, production data, or host filesystem paths are reachable.
- **Authentication & Database Schemas:** Main application authentication and persistent telemetry migrations remain reserved for Stage 5.
