# Detection ML Service (Stage 3 — Active)

## Purpose
The `detection/` service is a high-performance Python FastAPI service providing real-time security feature analysis, explainable threat scoring, and machine learning anomaly detection for the reverse-proxy gateway.

---

## Architecture & Endpoints

### 1. `GET /health`
Returns service health status, model load state, active model version, and uptime.

**Response:**
```json
{
  "status": "healthy",
  "service": "ml-detection-engine",
  "model_loaded": true,
  "model_version": "1.0.0-rf-synthetic",
  "uptime_seconds": 128.4
}
```

### 2. `POST /score`
Receives bounded, non-sensitive request metadata extracted by the gateway, runs dual-layer scoring (deterministic heuristic + scikit-learn anomaly model), and returns a risk score `[0.0, 1.0]`, classification label, and explainable evidence.

**Request Schema (`RequestFeatures`):**
```json
{
  "request_id": "993ee3b2-...",
  "method": "GET",
  "path": "/api/admin/config",
  "path_depth": 3,
  "path_entropy": 3.82,
  "has_traversal_tokens": false,
  "has_sqli_tokens": false,
  "has_shell_tokens": false,
  "has_sensitive_keyword": true,
  "ip_request_count_10s": 12,
  "missing_host": false,
  "missing_user_agent": false,
  "suspicious_user_agent": false,
  "body_size": 0,
  "header_count": 8,
  "failed_auth_count": 0
}
```

**Privacy Guarantee:** Raw credentials, cookies, authorization headers, passwords, and complete request bodies are strictly excluded from transmission to this service.

**Response Schema (`DetectionResult`):**
```json
{
  "request_id": "993ee3b2-...",
  "risk_score": 0.85,
  "classification": "MALICIOUS",
  "evidence": [
    "heuristic:sensitive_keyword_path",
    "heuristic:high_request_frequency",
    "ml_anomaly:score_0.84"
  ],
  "model_version": "1.0.0-rf-synthetic",
  "inference_duration_ms": 1.45
}
```

---

## Scoring Models

1. **Deterministic Heuristic Detector (`src/deterministic.py`):**
   - Evaluates weighted multi-factor indicators:
     - Path traversal sequences (`../`, `..%2f`)
     - SQL injection fragments (`union select`, `--`, `1=1`)
     - Shell injection metacharacters (`|`, `&&`, `;`, `` ` ``)
     - High Shannon path entropy (> 4.2)
     - Suspicious scanner user-agents (sqlmap, nikto, nmap)
     - Rapid request bursts (> 20 requests per 10s from IP)
     - Sensitive endpoint probes (`/admin`, `/.env`, `/actuator`, `/debug`)

2. **Scikit-Learn Anomaly Classifier (`src/ml_model.py`):**
   - Architecture: `StandardScaler` + `RandomForestClassifier(n_estimators=50, random_state=42)`.
   - Feature vector: 13 normalized numerical/boolean dimensions.
   - Evaluates non-linear feature interactions and outputs probability of anomaly.

3. **Combined Ensemble:**
   - Risk score is computed as `0.5 * heuristic_score + 0.5 * ml_score` (boosted if either model indicates high confidence attack).
   - Labels:
     - `BENIGN`: `risk_score < 0.40`
     - `SUSPICIOUS`: `0.40 <= risk_score < 0.70`
     - `MALICIOUS`: `risk_score >= 0.70`

---

## Training Pipeline & Limitations

### Model Training
Run `python train.py` inside `detection/` to generate `model.joblib`.
- Generates 2,000 synthetic benign requests and 500 synthetic attack requests simulating web probing, SQLi, scanning bursts, and traversal attempts.
- Evaluates test split with ROC-AUC and classification metrics.
- Serializes pipeline to `model.joblib`.

### Explicit Limitations of Synthetic Data
> **IMPORTANT:** The synthetic training data used in this baseline model simulates known heuristic patterns and statistical outliers. It **does NOT** represent real-world advanced persistent threats (APTs), polymorphic zero-day exploits, or authenticated insider threats. Real-world deployments require ongoing retraining on verified honeypot telemetry collected during Stage 4 and Stage 5.

---

## Local Development & Testing

```bash
# Setup virtual environment
cd detection
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Train model
python train.py

# Run test suite
pytest tests/test_detection.py

# Start standalone development server
uvicorn src.main:app --host 0.0.0.0 --port 8000
```
