# Deception Runtime Environment (Stage 4 — Active)

## Purpose
The `deception/` service provides an isolated, stateful active cyber deception runtime and Deception State Graph (DSG). It simulates a realistic enterprise web application using synthetic fixtures, provides session-isolated deception states, and executes controlled deception strategies without modifying protected safety policies.

> **IMPORTANT:** In Stage 4, this environment is fully built and tested as a standalone runtime. **Gateway traffic diversion is NOT activated.** The gateway continues operating strictly in Shadow Mode.

---

## 1. Architecture & Deception State Graph (DSG)

The runtime represents the simulated application as a validated, directed graph of distinct service nodes with strictly permitted transitions:

```
                  ┌───────────────┐
                  │  entrypoint   │
                  └──────┬────────┘
                         │
      ┌──────────┬───────┴───────┬──────────┐
      ▼          ▼               ▼          ▼
 ┌─────────┐ ┌───────┐      ┌─────────┐ ┌─────────┐
 │ catalog │ │ users │      │  files  │ │  auth   │
 └────┬────┘ └───┬───┘      └────┬────┘ └────┬────┘
      │          │               │           │
      └──────────┴───────┬───────┴───────────┘
                         ▼
                  ┌─────────────┐
                  │    admin    │  (Requires Admin Session Role)
                  └─────────────┘
```

### Graph Node Specifications

| Node ID | Service Type | State Version | Permitted Transitions | Access Requirement |
|---|---|---|---|---|
| `entrypoint` | `public` | 1 | `catalog`, `users`, `files`, `admin`, `auth` | Public / Anonymous |
| `catalog` | `catalog` | 1 | `entrypoint`, `users`, `files`, `admin`, `auth` | Public / Anonymous |
| `users` | `user_management` | 1 | `entrypoint`, `catalog`, `files`, `admin`, `auth` | Public / Anonymous |
| `files` | `document_store` | 1 | `entrypoint`, `catalog`, `users`, `admin`, `auth` | Public / Anonymous |
| `admin` | `admin_control` | 1 | `entrypoint`, `catalog`, `users`, `files`, `auth` | Role: `admin` |
| `auth` | `authentication` | 1 | `entrypoint`, `catalog`, `users`, `files`, `admin` | Public / Anonymous |

---

## 2. Three Logical State Layers

1. **Protected Policy Layer (`src/policy.ts`):**
   - Strictly immutable via deep recursive freezing (`Object.freeze`).
   - Defines allowed DSG nodes, authorized strategy actions, session limits, and hard safety constraints:
     - `preventCommandExecution`: `true`
     - `preventArbitraryNetworkEgress`: `true`
     - `preventHostFileSystemAccess`: `true`
     - `preventRealDatabaseAccess`: `true`
   - Runtime actions can never alter or override this layer.

2. **Controlled Dynamic Layer (`src/syntheticData.ts`, session-scoped):**
   - Deep-cloned per session to guarantee absolute multi-session isolation.
   - Contains mutable synthetic datasets:
     - Synthetic user directory (`dynamicUsers`)
     - Synthetic file metadata (`dynamicFiles`)
     - Synthetic service catalog (`dynamicServices`)
   - Decoy assets (such as `master_passwords_vault.kdbx` or decoy administrative APIs) are injected dynamically by the Strategy Selector.

3. **Observation Layer (`src/sessionStore.ts`, session-scoped):**
   - Records pseudonymous interaction history without storing personal credentials.
   - Tracks current DSG node, sequence of visited nodes, observation detail level (`standard` vs `high_detail`), and timestamps.

---

## 3. Synthetic API Contracts

### 3.1 `GET /health`
Returns runtime status, policy version, and session capacity metrics.
```json
{
  "status": "healthy",
  "service": "deception-runtime",
  "stage": "Stage 4 — Dynamic Deception Runtime and DSG",
  "policyVersion": "1.0.0-immutable",
  "activeSessions": 14,
  "uptime": 342.1,
  "timestamp": "2026-10-18T15:45:00.000Z"
}
```

### 3.2 `GET /api/catalog`
Returns available synthetic enterprise microservices.
```json
{
  "service": "catalog",
  "sessionId": "sess_f8a92...",
  "currentNode": "catalog",
  "totalCount": 4,
  "services": [
    {
      "id": "srv-syn-001",
      "name": "Identity & Authentication Gateway",
      "endpoint": "/api/auth",
      "status": "online",
      "version": "2.4.1",
      "isDecoy": false
    }
  ]
}
```

### 3.3 `GET /api/users`
Returns synthetic employee records. All emails end in `@synthetic.local`; no real personal data exists.
```json
{
  "service": "user_directory",
  "sessionId": "sess_f8a92...",
  "currentNode": "users",
  "totalCount": 4,
  "users": [
    {
      "id": "usr-syn-002",
      "username": "alice.jenkins",
      "email": "alice.jenkins@synthetic.local",
      "displayName": "Alice Jenkins",
      "role": "user",
      "department": "Core Infrastructure",
      "isDecoy": false
    }
  ]
}
```

### 3.4 `GET /api/files`
Returns synthetic file metadata (sizes, MIME types, SHA-256 checksums). Never accesses host storage.
```json
{
  "service": "file_store",
  "sessionId": "sess_f8a92...",
  "currentNode": "files",
  "totalCount": 5,
  "files": [
    {
      "id": "file-syn-003",
      "filename": "datacenter_vpn_profile.ovpn",
      "path": "/network/config/datacenter_vpn_profile.ovpn",
      "sizeBytes": 4210,
      "classification": "RESTRICTED",
      "checksumSha256": "d4735e...",
      "isDecoy": false
    }
  ]
}
```

### 3.5 `POST /api/auth/login`
Simulated authentication against explicitly documented synthetic test accounts.

**Test Accounts:**
- Administrator: `admin` / `admin@synthetic.local` — Password: `P@ssw0rd2026!` (Role: `admin`)
- Developer: `developer` / `developer@synthetic.local` — Password: `DevSecret2026!` (Role: `user`)
- Compliance Auditor: `auditor` / `auditor@synthetic.local` — Password: `AuditRead2026!` (Role: `auditor`)

**Success Response (HTTP 200):**
```json
{
  "status": "authenticated",
  "message": "Synthetic authentication successful.",
  "sessionId": "sess_f8a92...",
  "token": "syn_tok_1b93f...",
  "user": {
    "id": "usr-syn-001",
    "username": "admin",
    "email": "admin@synthetic.local",
    "role": "admin"
  }
}
```

### 3.6 `GET /api/admin`
Simulated administrative console.
- **Unauthenticated / Non-Admin:** Returns `401 Unauthorized` with error code `ADMIN_AUTH_REQUIRED`.
- **Authenticated Administrator:** Returns operational telemetry and honeypot interaction statistics.

---

## 4. Controlled Deception Strategy Selector

The strategy selector evaluates session context and chooses actions **strictly from an explicit allowlist**:

1. `ADD_SYNTHETIC_DECOY_RECORD`: Injects high-value decoy credentials/vaults into the session's dynamic file layer upon file probing.
2. `EXPOSE_SYNTHETIC_SERVICE`: Injects simulated legacy administrative APIs into the session's dynamic catalog upon service reconnaissance.
3. `INCREASE_OBSERVATION_DETAIL`: Escalates telemetry fidelity to `high_detail` when suspicious multi-node probing or burst requests occur.
4. `MAINTAIN_CURRENT_STATE`: Default safe state when no adaptation is required.
5. `DISABLE_DECEPTION`: Deactivates active deception state for a session.

**Safety Assurance:** Every proposed action is validated against `PROTECTED_POLICY.allowedStrategyActions`. Unrecognized actions are discarded. The selector executes zero model-generated code, shell invocations, or network requests.

---

## 5. Security & Isolation Model

- **No Host Port Exposure:** The container exposes port `5050` solely to the internal Docker bridge network (`deception-network`).
- **Unprivileged Runtime:** Executes under unprivileged system user `node` (`USER node` in Dockerfile).
- **Strict Sandboxing:** No volume mounts to the host filesystem, no access to Docker socket (`/var/run/docker.sock`), and zero production secrets.
- **Session Isolation:** Each session receives independent deep-cloned state. A compromise or decoy interaction in Session A cannot affect Session B.
- **Memory Safety:** In-memory store enforces sliding TTL (default 30m) and LRU capacity eviction (default 1000 sessions).

---

## 6. Local Testing & Verification

```bash
cd deception

# 1. Install dependencies
npm install

# 2. Build TypeScript
npm run build

# 3. Run automated acceptance tests
npm test

# 4. Start local development server
npm run dev
```
