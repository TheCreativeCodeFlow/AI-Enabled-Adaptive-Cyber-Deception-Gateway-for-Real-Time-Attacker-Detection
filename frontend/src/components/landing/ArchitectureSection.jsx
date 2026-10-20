import React from 'react';
import Card from '../ui/Card';
import Icon from '../ui/Icon';

/**
 * Cyber Deception Gateway — Technical Architecture Overview Section
 *
 * Depicts the relationship between:
 * 1. Incoming application traffic
 * 2. Gateway & routing layer (:8080)
 * 3. AI threat detection service (:8000)
 * 4. Policy evaluation engine
 * 5. Protected application origin (:5000)
 * 6. Isolated deception runtime (:5050)
 * 7. Logging, telemetry & evaluation (:4000 & PostgreSQL)
 */
export default function ArchitectureSection() {
  const components = [
    {
      name: 'Reverse-Proxy Gateway',
      port: ':8080',
      status: 'Implemented',
      role: 'Intercepts incoming HTTP traffic, manages session stickiness, and executes policy-directed request dispatching.',
    },
    {
      name: 'AI Threat Detection Service',
      port: ':8000',
      status: 'Implemented',
      role: 'Lightweight FastAPI service running calibrated ML models to calculate real-time request anomaly and threat scores.',
    },
    {
      name: 'Policy Evaluation Engine',
      port: 'Embedded in Gateway',
      status: 'Implemented',
      role: 'Evaluates scores against configured thresholds, manages sticky session persistence, and enforces fail-safe fallback policies.',
    },
    {
      name: 'Isolated Deception Runtime',
      port: ':5050',
      status: 'Implemented',
      role: 'Containerized synthetic environment presenting dynamic Deception State Graph (DSG) nodes to divert and trap attackers.',
    },
    {
      name: 'Protected Upstream Origin',
      port: ':5000 (or external FQDN)',
      status: 'Configurable Target',
      role: 'Legitimate customer web application shielded from malicious probes, receiving only verified benign requests.',
    },
    {
      name: 'Security Event Pipeline & Audit',
      port: ':4000 / PostgreSQL',
      status: 'Implemented',
      role: 'Ingests security event streams, records operator audit logs, and calculates Deception Effectiveness Scores (DES).',
    },
  ];

  return (
    <section id="architecture" className="section section-alt">
      <div className="container">
        <div className="section-header">
          <span className="section-eyebrow">System Architecture</span>
          <h2 className="section-title">Coordinated Defense Topology</h2>
          <p className="section-description">
            A distributed, microservice-based architecture ensuring strict isolation between attacker engagement layers and upstream production workloads.
          </p>
        </div>

        {/* Visual Architecture Flow Diagram */}
        <div
          style={{
            backgroundColor: 'var(--bg-card)',
            border: '1px solid var(--border-subtle)',
            borderRadius: 'var(--radius-lg)',
            padding: '2rem 1.5rem',
            marginBottom: '3rem',
            boxShadow: '0 12px 36px rgba(0, 0, 0, 0.3)',
          }}
        >
          <div style={{ marginBottom: '1.5rem', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.5rem' }}>
            <div>
              <h3 style={{ fontSize: '1.1rem', fontWeight: 700, color: 'var(--text-main)', marginBottom: '0.2rem' }}>
                Technical Dataflow & Routing Topology
              </h3>
              <p style={{ fontSize: '0.825rem', color: 'var(--text-muted)' }}>
                Direct request evaluation, asynchronous event streaming, and isolated sandbox execution
              </p>
            </div>
            <span
              style={{
                fontSize: '0.75rem',
                fontFamily: 'var(--font-mono)',
                backgroundColor: 'rgba(92, 225, 214, 0.1)',
                color: 'var(--accent-secondary)',
                border: '1px solid var(--accent-secondary-border)',
                padding: '0.25rem 0.6rem',
                borderRadius: 'var(--radius-sm)',
              }}
            >
              Docker Cluster Topology
            </span>
          </div>

          <svg
            viewBox="0 0 860 300"
            style={{ width: '100%', height: 'auto', display: 'block' }}
            aria-label="Microservice architecture flowchart detailing gateway, detection, origin, deception, and backend services"
          >
            <defs>
              <marker id="arch-arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                <path d="M 0 1 L 9 5 L 0 9 z" fill="#3D5680" />
              </marker>
              <marker id="arch-arrow-cyan" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                <path d="M 0 1 L 9 5 L 0 9 z" fill="#5CE1D6" />
              </marker>
              <marker id="arch-arrow-blue" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                <path d="M 0 1 L 9 5 L 0 9 z" fill="#5B9CFF" />
              </marker>
              <marker id="arch-arrow-green" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                <path d="M 0 1 L 9 5 L 0 9 z" fill="#10B981" />
              </marker>
            </defs>

            {/* Ingress to Gateway */}
            <line x1="90" y1="130" x2="160" y2="130" stroke="#5B9CFF" strokeWidth="2" markerEnd="url(#arch-arrow-blue)" />

            {/* Gateway <-> Detection (Synchronous RPC) */}
            <line x1="260" y1="90" x2="260" y2="45" stroke="#5CE1D6" strokeWidth="2" strokeDasharray="3 3" />
            <line x1="280" y1="45" x2="280" y2="90" stroke="#5CE1D6" strokeWidth="2" strokeDasharray="3 3" />

            {/* Gateway -> Origin (Forward Benign) */}
            <path d="M 370 115 C 440 115, 470 50, 540 50" fill="none" stroke="#10B981" strokeWidth="2" markerEnd="url(#arch-arrow-green)" />

            {/* Gateway -> Deception Runtime (Divert Malicious) */}
            <path d="M 370 145 C 440 145, 470 210, 540 210" fill="none" stroke="#5B9CFF" strokeWidth="2" markerEnd="url(#arch-arrow-blue)" />

            {/* Gateway -> Backend Pipeline (Async Event Stream) */}
            <path d="M 270 170 L 270 250 L 540 270" fill="none" stroke="#64758F" strokeWidth="1.5" strokeDasharray="4 4" markerEnd="url(#arch-arrow)" />

            {/* Backend -> PostgreSQL */}
            <line x1="720" y1="270" x2="770" y2="270" stroke="#64758F" strokeWidth="1.5" markerEnd="url(#arch-arrow)" />

            {/* NODE: INCOMING INTERNET */}
            <g transform="translate(10, 100)">
              <rect width="80" height="60" rx="6" fill="#080D18" stroke="#1C283F" strokeWidth="1.5" />
              <text x="40" y="28" textAnchor="middle" fill="#F4F7FC" fontSize="11" fontWeight="700">Internet</text>
              <text x="40" y="44" textAnchor="middle" fill="#9AAAC0" fontSize="9">Port 80/443</text>
            </g>

            {/* NODE: GATEWAY (Core) */}
            <g transform="translate(160, 90)">
              <rect width="210" height="80" rx="8" fill="#0D1422" stroke="#5B9CFF" strokeWidth="2" />
              <text x="105" y="28" textAnchor="middle" fill="#5B9CFF" fontSize="12" fontWeight="700">deception-gateway</text>
              <text x="105" y="46" textAnchor="middle" fill="#F4F7FC" fontSize="11" fontWeight="600">Reverse Proxy & Policy Router</text>
              <text x="105" y="64" textAnchor="middle" fill="#9AAAC0" fontSize="9.5">Port 8080 · Session Stickiness</text>
            </g>

            {/* NODE: DETECTION SERVICE */}
            <g transform="translate(200, 10)">
              <rect width="180" height="42" rx="6" fill="#080D18" stroke="#5CE1D6" strokeWidth="1.5" />
              <text x="90" y="20" textAnchor="middle" fill="#5CE1D6" fontSize="10.5" fontWeight="700">deception-detection</text>
              <text x="90" y="34" textAnchor="middle" fill="#9AAAC0" fontSize="9">Port 8000 · FastAPI ML Model</text>
            </g>

            {/* NODE: PROTECTED ORIGIN */}
            <g transform="translate(540, 20)">
              <rect width="210" height="60" rx="8" fill="#080D18" stroke="#10B981" strokeWidth="1.5" />
              <text x="105" y="26" textAnchor="middle" fill="#10B981" fontSize="11" fontWeight="700">Upstream Protected Origin</text>
              <text x="105" y="44" textAnchor="middle" fill="#9AAAC0" fontSize="9.5">deception-test-origin (:5000)</text>
            </g>

            {/* NODE: DECEPTION RUNTIME */}
            <g transform="translate(540, 180)">
              <rect width="210" height="60" rx="8" fill="#080D18" stroke="#5B9CFF" strokeWidth="1.5" />
              <text x="105" y="26" textAnchor="middle" fill="#5B9CFF" fontSize="11" fontWeight="700">deception-runtime</text>
              <text x="105" y="44" textAnchor="middle" fill="#9AAAC0" fontSize="9.5">Port 5050 · Isolated Synthetic DSG</text>
            </g>

            {/* NODE: BACKEND EVENT PIPELINE */}
            <g transform="translate(540, 250)">
              <rect width="180" height="42" rx="6" fill="#080D18" stroke="#374E76" strokeWidth="1.2" />
              <text x="90" y="20" textAnchor="middle" fill="#F4F7FC" fontSize="10" fontWeight="600">deception-backend (:4000)</text>
              <text x="90" y="34" textAnchor="middle" fill="#9AAAC0" fontSize="8.5">Event Ingestion & Audit Pipeline</text>
            </g>

            {/* NODE: POSTGRES */}
            <g transform="translate(770, 250)">
              <rect width="80" height="42" rx="6" fill="#080D18" stroke="#263857" strokeWidth="1.2" />
              <text x="40" y="20" textAnchor="middle" fill="#9AAAC0" fontSize="10" fontWeight="600">PostgreSQL</text>
              <text x="40" y="34" textAnchor="middle" fill="#64758F" fontSize="8.5">:5432</text>
            </g>
          </svg>
        </div>

        {/* Microservice Component Inventory */}
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))',
            gap: '1.5rem',
          }}
        >
          {components.map((comp) => (
            <Card key={comp.name} style={{ padding: '1.5rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.75rem' }}>
                <span style={{ fontSize: '0.8rem', fontFamily: 'var(--font-mono)', color: 'var(--accent-primary)', fontWeight: 600 }}>
                  {comp.port}
                </span>
                <span
                  style={{
                    fontSize: '0.7rem',
                    textTransform: 'uppercase',
                    color: 'var(--text-muted)',
                    backgroundColor: 'rgba(255, 255, 255, 0.04)',
                    padding: '0.15rem 0.45rem',
                    borderRadius: 'var(--radius-sm)',
                    border: '1px solid var(--border-subtle)',
                  }}
                >
                  {comp.status}
                </span>
              </div>
              <h4 style={{ fontSize: '1.05rem', fontWeight: 700, color: 'var(--text-main)', marginBottom: '0.5rem' }}>
                {comp.name}
              </h4>
              <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', lineHeight: 1.55 }}>
                {comp.role}
              </p>
            </Card>
          ))}
        </div>
      </div>
    </section>
  );
}
