# Detection ML Service (Reserved — Stage 3)

## Purpose
The `detection/` service will provide a Python-based machine learning inference engine for real-time anomaly detection and attacker intent scoring.

## Planned Responsibilities
- Receive extracted request features and telemetry from the `gateway/` reverse proxy.
- Evaluate session behavior, sequence patterns, and payload anomalies using trained ML models.
- Output real-time risk scores, confidence intervals, and attacker classification.
- Feed actionable telemetry into the `backend/` persistence layer and audit log.

## Implementation Stage
- **Current State:** Reserved directory (Stage 1).
- **Target Implementation:** Stage 3 (Python ML Service & Anomaly Detection).
