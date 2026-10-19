import re
import urllib.parse
from typing import Tuple, List
from .schemas import RequestFeatures

SENSITIVE_PATH_PATTERNS = [
    re.compile(r'/\.env', re.IGNORECASE),
    re.compile(r'/\.git', re.IGNORECASE),
    re.compile(r'/\.aws', re.IGNORECASE),
    re.compile(r'/etc/(passwd|shadow|group)', re.IGNORECASE),
    re.compile(r'/proc/', re.IGNORECASE),
    re.compile(r'/wp-(admin|login|config)', re.IGNORECASE),
    re.compile(r'/phpmyadmin', re.IGNORECASE),
    re.compile(r'/actuator', re.IGNORECASE),
    re.compile(r'/aws/', re.IGNORECASE),
    re.compile(r'/(root|cgi-bin)/', re.IGNORECASE),
    re.compile(r'/admin(/|\b)', re.IGNORECASE),
    re.compile(r'/server-status', re.IGNORECASE),
    re.compile(r'/solr/', re.IGNORECASE),
    re.compile(r'/swagger-ui', re.IGNORECASE),
    re.compile(r'/api-docs', re.IGNORECASE),
    re.compile(r'/console/', re.IGNORECASE),
]

ATTACK_SIGNATURE_PATTERNS = [
    (re.compile(r"(\bor\b\s+['\"\d]|\band\b\s+['\"\d]|\bunion\b\s+(all\s+)?select|\bdrop\b\s+table|;\s*--|sleep\s*\(\d+\)|'\s*--|--|having\s+1=1|case\s+when|\bselect\b\s+.*\bfrom\b)", re.IGNORECASE), "SQL injection attack signature detected"),
    (re.compile(r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.\.%2f|/etc/(passwd|shadow|group)|/proc/self|/boot/|/sys/|\\windows\\)", re.IGNORECASE), "Path traversal directory escape sequence detected"),
    (re.compile(r"((;|\||&&)\s*(cat|id|whoami|uname|rm|nc|sleep|bash|sh|curl|wget)\b|\$\((id|whoami)\)|`id`|cmd=\s*(whoami|cat|id|uname)|/shell\b)", re.IGNORECASE), "OS command injection execution pattern detected"),
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
    decoded_path = urllib.parse.unquote(features.path)

    # 1. Suspicious keywords in path
    if features.has_suspicious_keywords or features.suspicious_keyword_count > 0:
        count = max(features.suspicious_keyword_count, 1)
        keyword_penalty = min(0.15 * count, 0.40)
        score += keyword_penalty
        evidence.append(f"Matched {count} suspicious token(s) in path")

    # 2. Sensitive target endpoints
    for pattern in SENSITIVE_PATH_PATTERNS:
        if pattern.search(decoded_path):
            score += 0.75
            evidence.append(f"Path matches sensitive target pattern: {pattern.pattern}")
            break

    # 2b. Exploit payload signatures
    for pattern, desc in ATTACK_SIGNATURE_PATTERNS:
        if pattern.search(decoded_path):
            score += 0.75
            evidence.append(desc)
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
    if features.auth_failure_count >= 3:
        score += 0.35
        evidence.append(
            f"Repeated authentication failures ({features.auth_failure_count})"
        )
    elif features.auth_failure_count >= 1:
        score += 0.15
        evidence.append(
            f"Authentication failure recorded ({features.auth_failure_count})"
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
