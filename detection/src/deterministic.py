import re
from typing import Tuple, List
from .schemas import RequestFeatures

SENSITIVE_PATH_PATTERNS = [
    re.compile(r'/\.env', re.IGNORECASE),
    re.compile(r'/\.git', re.IGNORECASE),
    re.compile(r'/etc/passwd', re.IGNORECASE),
    re.compile(r'/proc/', re.IGNORECASE),
    re.compile(r'/wp-admin', re.IGNORECASE),
    re.compile(r'/wp-login', re.IGNORECASE),
    re.compile(r'/phpmyadmin', re.IGNORECASE),
    re.compile(r'/actuator', re.IGNORECASE),
    re.compile(r'/aws/', re.IGNORECASE),
]


def evaluate_deterministic_baseline(features: RequestFeatures) -> Tuple[float, List[str]]:
    """
    Evaluates request features against an explainable, deterministic rule set.
    Returns:
        (risk_score, evidence_list)
        risk_score is strictly in range [0.0, 1.0].
    """
    score = 0.0
    evidence: List[str] = []

    # 1. Suspicious keywords in path
    if features.has_suspicious_keywords or features.suspicious_keyword_count > 0:
        count = max(features.suspicious_keyword_count, 1)
        keyword_penalty = min(0.15 * count, 0.40)
        score += keyword_penalty
        evidence.append(f"Matched {count} suspicious token(s) in path")

    # 2. Sensitive target endpoints
    for pattern in SENSITIVE_PATH_PATTERNS:
        if pattern.search(features.path):
            score += 0.35
            evidence.append(f"Path matches sensitive target pattern: {pattern.pattern}")
            break

    # 3. Scanner / tool signatures in headers
    if features.suspicious_header_patterns:
        header_penalty = min(0.20 * len(features.suspicious_header_patterns), 0.40)
        score += header_penalty
        evidence.append(
            f"Suspicious header signature(s): {', '.join(features.suspicious_header_patterns)}"
        )

    # 4. Missing standard headers
    if features.missing_expected_headers:
        missing_penalty = min(0.10 * len(features.missing_expected_headers), 0.20)
        score += missing_penalty
        evidence.append(
            f"Missing expected standard header(s): {', '.join(features.missing_expected_headers)}"
        )

    # 5. Elevated request frequency
    if features.request_frequency > 15.0:
        score += 0.25
        evidence.append(
            f"High request frequency ({features.request_frequency:.1f} req/s) indicating automated scanning"
        )
    elif features.request_frequency > 8.0:
        score += 0.10
        evidence.append(
            f"Elevated request frequency ({features.request_frequency:.1f} req/s)"
        )

    # 6. High path entropy (potential obfuscation)
    if features.path_entropy > 4.2:
        score += 0.15
        evidence.append(
            f"High path entropy ({features.path_entropy:.2f}) suggesting obfuscation or randomized identifiers"
        )

    # 7. Consecutive auth failures
    if features.auth_failure_count >= 5:
        score += 0.30
        evidence.append(
            f"High authentication failure count ({features.auth_failure_count})"
        )
    elif features.auth_failure_count >= 2:
        score += 0.15
        evidence.append(
            f"Multiple authentication failures ({features.auth_failure_count})"
        )

    # 8. Decoy interactions
    if features.decoy_interactions > 0:
        score += 0.45
        evidence.append(
            f"Encounter with decoy/honeypot asset recorded ({features.decoy_interactions})"
        )

    # Default clean message if no evidence accumulated
    if not evidence:
        evidence.append("Clean request: no anomalous indicators identified by deterministic rules")

    # Strictly bound score in [0.0, 1.0]
    final_score = round(max(0.0, min(1.0, score)), 4)
    return final_score, evidence
