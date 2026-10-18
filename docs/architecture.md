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
        DecoyEnv[Deception Runtime<br/>Dynamic Honeypots & Decoy Services<br/><i>deception/ - Stage 4</i>]
    end

    Client -->|HTTP/HTTPS| Gateway
    Gateway -->|Feature Stream & Telemetry (Shadow Mode)| MLService
    MLService -->|Threat Score & Classification| Gateway

    Gateway -->|Benign Traffic Routing| Backend
    Gateway -.->|Future Diverted Traffic (Stage 4)| DecoyEnv

    Frontend -->|Admin & Status Queries| Backend
    Backend -->|Read/Write State| DB
    DecoyEnv -.->|Sanitized Audit Logs| Backend

    classDef active fill:#1b5e20,stroke:#4caf50,color:#fff;
    classDef planned fill:#424242,stroke:#9e9e9e,color:#fff,stroke-dasharray: 5 5;
    class Backend,Frontend,DB,Gateway,MLService active;
    class DecoyEnv planned;
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

### 3.5 `deception/` (Stage 4 — Reserved)
- **Tech Stack:** Containerized shadow runtimes, dynamic mock services, synthetic databases, and canary tokens.
- **Role:** Absorbs diverted attacker traffic. Provides realistic, believable interactions while strictly confining network egress to prevent pivot attacks.

### 3.6 `infra/` (Stage 1 — Active)
- **Tech Stack:** Docker, Docker Compose, PostgreSQL 16.
- **Role:** Declarative local and staging infrastructure management. Provides reproducible service orchestration and verified healthchecks.

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
 [ Backend & Database ]        [ Deception Honeypots ]
```

1. **Perimeter Boundary (Untrusted to DMZ):** Only the Gateway service exposes public ports. No internal backend services or databases are accessible directly from the public network.
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

### 5.2 Malicious Traffic Flow (Stage 3 Shadow Mode vs Stage 4 Deception)
1. Adversary executes scanning, SQL injection, path traversal, or probe requests against Gateway.
2. Gateway extracts derived features and queries Detection service.
3. Detection engine flags malicious patterns (`score >= 0.70`, label `MALICIOUS`) with evidence factors.
4. **Stage 3 (Shadow Mode):** Gateway logs classification and security evidence, sets telemetry headers, but **does not block or divert**. Traffic continues to the authorized test origin to validate detector fidelity without service interruption.
5. **Stage 4 (Future Deception Runtime):** Gateway will transparently divert sessions to `deception/` honeypot environment, presenting synthetic responses and sandboxed decoy targets.

---

## 6. Staged Implementation Plan

| Stage | Focus Area | Deliverables | Current Status |
|---|---|---|---|
| **Stage 1** | **Repository Foundation & Architecture** | Modular directory layout, minimal React frontend, Express TypeScript backend with `GET /health`, Docker Compose orchestration, PostgreSQL healthcheck, architecture documentation. | **Active / Complete** |
| **Stage 2** | **Gateway & Traffic Interception** | Reverse-proxy service in `gateway/`, request inspection pipeline, routing policies, configurable routing rules, isolated test origin. | **Active / Complete** |
| **Stage 3** | **ML Detection Engine & Gateway Integration** | Python FastAPI ML service in `detection/`, feature extraction, dual deterministic + scikit-learn models, shadow mode gateway integration, fail-open resilience. | **Active / Complete** |
| **Stage 4** | **Dynamic Deception Runtime** | Sandboxed honeypot containers in `deception/`, decoy targets, canary token generator, lateral egress barriers. | *Reserved* |
| **Stage 5** | **Dashboard, Telemetry & SIEM** | Interactive threat visualization in `frontend/`, attack graph replay, alert notifications, SIEM event export. | *Reserved* |

---

## 7. Current State & Known Limitations (Stage 3)

- **Shadow Mode Traffic Execution:** In Stage 3, all requests are forwarded directly to the authorized upstream origin (`test-origin`), regardless of whether the detection service classifies them as `BENIGN`, `SUSPICIOUS`, or `MALICIOUS`. Dynamic redirection into honeypots is strictly reserved for Stage 4.
- **Fail-Open Resilience:** If the detection service is unreachable or exceeds the response timeout (default 500ms), the gateway continues proxying without returning client errors.
- **Synthetic Training Data Limitations:** The machine learning baseline is trained on synthetic feature distributions generated by `detection/train.py`. While it provides verified classification across structured anomalies, it does not represent real-world zero-day attack distributions. Production deployments will require continuous online retraining on authenticated honeypot telemetry.
- **Authentication & Database Schemas:** Application authentication and database migrations remain reserved for subsequent stages.
