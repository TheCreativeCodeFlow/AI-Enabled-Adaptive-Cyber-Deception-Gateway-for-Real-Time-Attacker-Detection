# Infrastructure Configuration (Stage 1)

This directory contains containerization, orchestration, and infrastructure manifests for local development and future deployment stages.

## Contents
- `docker-compose.yml`: Standard Compose file referencing the microservices.
- Service definitions:
  - `postgres`: PostgreSQL 16 Alpine with native `pg_isready` healthcheck.
  - `backend`: Node.js Express TypeScript API with `/health` healthcheck.
  - `frontend`: React Vite landing page with HTTP healthcheck.

## Local Execution
From project root:
```bash
docker compose up -d --build
```

Or using this infrastructure file directly:
```bash
docker compose -f infra/docker-compose.yml up -d --build
```
