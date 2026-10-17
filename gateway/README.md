# Gateway Service (Reserved — Stage 2)

## Purpose
The `gateway/` service will act as the reverse-proxy entry point for all incoming network traffic.

## Planned Responsibilities
- Terminate client TLS/HTTP connections.
- Perform real-time request inspection and feature extraction.
- Query the `detection/` ML service for threat and anomaly scores.
- Dynamically route benign requests to legitimate upstream services and suspected malicious requests to the isolated `deception/` runtime.
- Inject deception tokens and honeypot traps into responses where directed by policy.

## Implementation Stage
- **Current State:** Reserved directory (Stage 1).
- **Target Implementation:** Stage 2 (Reverse-Proxy Gateway & Traffic Interception).
