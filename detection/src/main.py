import time
from datetime import datetime, timezone
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from .schemas import RequestFeatures, DetectionResult, HealthResponse
from .deterministic import evaluate_deterministic_baseline
from .ml_model import load_model, predict_anomaly_score

START_TIME = time.time()
MODEL_VERSION = "0.3.0-synthetic-baseline"
ml_pipeline = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global ml_pipeline
    # Load or train baseline model at startup
    ml_pipeline = load_model()
    yield
    ml_pipeline = None


app = FastAPI(
    title="AI-Enabled Cyber Deception Detection Engine",
    description="Real-time request feature analysis and risk scoring service",
    version=MODEL_VERSION,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """
    Service health check endpoint.
    """
    return HealthResponse(
        status="healthy",
        service="detection",
        stage="Stage 3 — ML Detection Engine",
        model_version=MODEL_VERSION,
        model_loaded=ml_pipeline is not None,
        timestamp=datetime.now(timezone.utc).isoformat(),
        uptime=round(time.time() - START_TIME, 2),
    )


@app.post("/score", response_model=DetectionResult)
async def score_request(features: RequestFeatures):
    """
    Analyzes request metadata and computes an explainable risk score.
    Combines deterministic rule evaluation with scikit-learn anomaly scoring.
    """
    start_inference = time.perf_counter()

    # 1. Deterministic baseline score and evidence
    base_score, evidence = evaluate_deterministic_baseline(features)

    # 2. ML statistical anomaly score
    ml_score, ml_conf = 0.0, 0.5
    if ml_pipeline is not None:
        ml_score, ml_conf = predict_anomaly_score(ml_pipeline, features)

    # 3. Blended risk score (strictly bounded in [0.0, 1.0])
    blended_score = round(max(0.0, min(1.0, (0.5 * base_score) + (0.5 * ml_score))), 4)

    # 4. Multi-factor classification
    if blended_score >= 0.70:
        classification = "MALICIOUS"
    elif blended_score >= 0.35:
        classification = "SUSPICIOUS"
    else:
        classification = "BENIGN"

    # Append ML insight to explainability list
    if ml_score >= 0.50:
        evidence.append(
            f"Statistical ML model evaluated {ml_score * 100:.1f}% anomaly probability"
        )

    # Compute confidence
    confidence = round(max(0.0, min(1.0, (0.5 + abs(blended_score - 0.5)))), 4)
    duration_ms = round((time.perf_counter() - start_inference) * 1000, 3)

    return DetectionResult(
        request_id=features.request_id,
        risk_score=blended_score,
        classification=classification,
        confidence=confidence,
        evidence=evidence,
        baseline_score=base_score,
        ml_anomaly_score=ml_score,
        model_version=MODEL_VERSION,
        inference_duration_ms=duration_ms,
    )


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """
    Catches unhandled errors and returns controlled JSON without stack traces.
    """
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "InternalServerError",
            "message": "Detection engine encountered an unexpected error.",
        },
    )
