from typing import List, Optional
from pydantic import BaseModel, Field


class RequestFeatures(BaseModel):
    """
    Extracted request metadata schema.
    Contains ONLY derived features; never raw credentials, cookies, or bodies.
    """
    request_id: str = Field(..., min_length=1, description="Correlation UUID for tracing")
    method: str = Field(default="GET", description="HTTP request method")
    path: str = Field(..., min_length=1, description="Normalized URL path")
    path_depth: int = Field(default=1, ge=0, description="Directory segment depth")
    path_length: int = Field(default=1, ge=0, description="Character length of path")
    path_entropy: float = Field(default=0.0, ge=0.0, description="Shannon entropy of path")
    has_suspicious_keywords: bool = Field(default=False, description="Flag for suspicious path keywords")
    suspicious_keyword_count: int = Field(default=0, ge=0, description="Count of matched suspicious tokens")
    query_param_count: int = Field(default=0, ge=0, description="Count of query parameters")
    query_entropy: float = Field(default=0.0, ge=0.0, description="Shannon entropy of query string")
    header_count: int = Field(default=0, ge=0, description="Total count of headers")
    missing_expected_headers: List[str] = Field(default_factory=list, description="Expected standard headers missing")
    suspicious_header_patterns: List[str] = Field(default_factory=list, description="Scanner or attack tool signatures detected")
    body_size: int = Field(default=0, ge=0, description="Request body size in bytes")
    content_type: Optional[str] = Field(default=None, description="Reported MIME Content-Type")
    request_frequency: float = Field(default=1.0, ge=0.0, description="Client request frequency (req/sec)")
    auth_failure_count: int = Field(default=0, ge=0, description="Consecutive authentication failures")
    decoy_interactions: int = Field(default=0, ge=0, description="Encounters with decoy or honeypot endpoints")
    client_ip: str = Field(default="unknown", description="Client IP address for telemetry correlation")


class DetectionResult(BaseModel):
    """
    Risk scoring and explainable classification output.
    """
    request_id: str
    risk_score: float = Field(..., ge=0.0, le=1.0, description="Overall blended risk score [0.0, 1.0]")
    classification: str = Field(..., description="Classification category: BENIGN, SUSPICIOUS, MALICIOUS")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence interval of classification [0.0, 1.0]")
    evidence: List[str] = Field(default_factory=list, description="Explainability reasons contributing to the score")
    baseline_score: float = Field(..., ge=0.0, le=1.0, description="Deterministic rule-based baseline score")
    ml_anomaly_score: float = Field(..., ge=0.0, le=1.0, description="Statistical ML anomaly score")
    model_version: str
    inference_duration_ms: float


class HealthResponse(BaseModel):
    """
    Health check response model.
    """
    status: str
    service: str
    stage: str
    model_version: str
    model_loaded: bool
    timestamp: str
    uptime: float
