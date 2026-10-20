import React, { useState } from 'react';
import Icon from '../ui/Icon';

/**
 * Cyber Deception Gateway — Gateway Architecture Visual Representation
 *
 * Illustrates:
 * 1. Users / Internet
 * 2. Cyber Deception Gateway
 * 3. AI Detection & Policy Evaluation
 * 4. Three Traffic Outcomes:
 *    - Legitimate traffic -> Configured Origin
 *    - Suspicious traffic -> Observation / Controlled Handling
 *    - Malicious traffic -> Deception Environment (according to policy)
 */
export default function GatewayDiagram() {
  const [activeOutcome, setActiveOutcome] = useState('malicious'); // 'legitimate' | 'suspicious' | 'malicious'

  const outcomes = {
    legitimate: {
      name: 'Legitimate Traffic',
      score: '0.12 (Low Risk)',
      classification: 'BENIGN',
      decision: 'ORIGIN',
      destination: 'Configured Origin Server (:5000)',
      color: '#10B981',
      bgColor: 'rgba(16, 185, 129, 0.1)',
      borderColor: 'rgba(16, 185, 129, 0.35)',
      description: 'Request passes validation checks and routes directly to the upstream application origin with standard low-latency proxy forwarding.',
    },
    suspicious: {
      name: 'Suspicious Traffic',
      score: '0.58 (Moderate Risk)',
      classification: 'EVALUATE',
      decision: 'OBSERVE / ENRICH',
      destination: 'Observation & Telemetry Pipeline',
      color: '#F59E0B',
      bgColor: 'rgba(245, 158, 11, 0.1)',
      borderColor: 'rgba(245, 158, 11, 0.35)',
      description: 'Unusual patterns trigger session tracking and granular telemetry logging without immediately dropping the connection.',
    },
    malicious: {
      name: 'Malicious Traffic',
      score: '0.94 (High Threat)',
      classification: 'MALICIOUS',
      decision: 'DECEPTION',
      destination: 'Isolated Deception Runtime (:5050)',
      color: '#5B9CFF',
      altColor: '#EF4444',
      bgColor: 'rgba(91, 156, 255, 0.1)',
      borderColor: 'rgba(91, 156, 255, 0.35)',
      description: 'Confirmed exploit payloads (e.g. SQLi, path traversal) divert automatically into the synthetic Deception State Graph, shielding the origin.',
    },
  };

  const current = outcomes[activeOutcome];

  return (
    <div
      style={{
        backgroundColor: 'var(--bg-card)',
        border: '1px solid var(--border-subtle)',
        borderRadius: 'var(--radius-lg)',
        overflow: 'hidden',
        boxShadow: '0 20px 48px rgba(0, 0, 0, 0.4)',
      }}
    >
      {/* Simulation Selector Bar */}
      <div
        style={{
          padding: '1rem 1.25rem',
          backgroundColor: 'rgba(13, 20, 34, 0.8)',
          borderBottom: '1px solid var(--border-subtle)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '0.75rem',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <span style={{ fontSize: '0.75rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em', color: 'var(--text-muted)' }}>
            Traffic Simulation:
          </span>
        </div>

        <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap' }}>
          <button
            type="button"
            onClick={() => setActiveOutcome('legitimate')}
            style={{
              padding: '0.35rem 0.75rem',
              borderRadius: 'var(--radius-sm)',
              fontSize: '0.75rem',
              fontWeight: 600,
              backgroundColor: activeOutcome === 'legitimate' ? 'rgba(16, 185, 129, 0.15)' : 'rgba(255, 255, 255, 0.04)',
              color: activeOutcome === 'legitimate' ? '#10B981' : 'var(--text-secondary)',
              border: `1px solid ${activeOutcome === 'legitimate' ? 'rgba(16, 185, 129, 0.4)' : 'var(--border-subtle)'}`,
              transition: 'all var(--transition-fast)',
            }}
          >
            Legitimate
          </button>
          <button
            type="button"
            onClick={() => setActiveOutcome('suspicious')}
            style={{
              padding: '0.35rem 0.75rem',
              borderRadius: 'var(--radius-sm)',
              fontSize: '0.75rem',
              fontWeight: 600,
              backgroundColor: activeOutcome === 'suspicious' ? 'rgba(245, 158, 11, 0.15)' : 'rgba(255, 255, 255, 0.04)',
              color: activeOutcome === 'suspicious' ? '#F59E0B' : 'var(--text-secondary)',
              border: `1px solid ${activeOutcome === 'suspicious' ? 'rgba(245, 158, 11, 0.4)' : 'var(--border-subtle)'}`,
              transition: 'all var(--transition-fast)',
            }}
          >
            Suspicious
          </button>
          <button
            type="button"
            onClick={() => setActiveOutcome('malicious')}
            style={{
              padding: '0.35rem 0.75rem',
              borderRadius: 'var(--radius-sm)',
              fontSize: '0.75rem',
              fontWeight: 600,
              backgroundColor: activeOutcome === 'malicious' ? 'rgba(91, 156, 255, 0.15)' : 'rgba(255, 255, 255, 0.04)',
              color: activeOutcome === 'malicious' ? 'var(--accent-primary)' : 'var(--text-secondary)',
              border: `1px solid ${activeOutcome === 'malicious' ? 'var(--accent-primary-border)' : 'var(--border-subtle)'}`,
              transition: 'all var(--transition-fast)',
            }}
          >
            Malicious (Diverted)
          </button>
        </div>
      </div>

      {/* Diagram Canvas */}
      <div style={{ padding: '2rem 1.5rem', position: 'relative' }}>
        <svg
          viewBox="0 0 740 260"
          style={{ width: '100%', height: 'auto', display: 'block', overflow: 'visible' }}
          aria-label="Gateway architecture flowchart showing traffic from users through gateway and AI detection to three outcomes"
        >
          <defs>
            {/* Arrow Markers */}
            <marker id="arrow-default" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
              <path d="M 0 1 L 9 5 L 0 9 z" fill="#2E4369" />
            </marker>
            <marker id="arrow-legitimate" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
              <path d="M 0 1 L 9 5 L 0 9 z" fill="#10B981" />
            </marker>
            <marker id="arrow-suspicious" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
              <path d="M 0 1 L 9 5 L 0 9 z" fill="#F59E0B" />
            </marker>
            <marker id="arrow-malicious" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
              <path d="M 0 1 L 9 5 L 0 9 z" fill="#5B9CFF" />
            </marker>
          </defs>

          {/* Connection Lines */}
          {/* 1. Client to Gateway */}
          <line
            x1="120"
            y1="130"
            x2="220"
            y2="130"
            stroke="var(--accent-primary)"
            strokeWidth="2.5"
            strokeDasharray={activeOutcome === 'malicious' ? '4 4' : 'none'}
            markerEnd="url(#arrow-default)"
          />

          {/* 2. Gateway to AI Detection (Bi-directional check) */}
          <line
            x1="310"
            y1="90"
            x2="310"
            y2="55"
            stroke="#5CE1D6"
            strokeWidth="2"
            strokeDasharray="3 3"
          />

          {/* 3. Outcomes Fan-out from Gateway (x=400, y=130) */}
          {/* Outcome A: Top -> Legitimate / Origin */}
          <path
            d="M 400 130 C 460 130, 480 50, 540 50"
            fill="none"
            stroke={activeOutcome === 'legitimate' ? '#10B981' : '#1E2D47'}
            strokeWidth={activeOutcome === 'legitimate' ? '3' : '1.5'}
            markerEnd={activeOutcome === 'legitimate' ? 'url(#arrow-legitimate)' : 'url(#arrow-default)'}
          />

          {/* Outcome B: Middle -> Suspicious / Observation */}
          <path
            d="M 400 130 L 540 130"
            fill="none"
            stroke={activeOutcome === 'suspicious' ? '#F59E0B' : '#1E2D47'}
            strokeWidth={activeOutcome === 'suspicious' ? '3' : '1.5'}
            markerEnd={activeOutcome === 'suspicious' ? 'url(#arrow-suspicious)' : 'url(#arrow-default)'}
          />

          {/* Outcome C: Bottom -> Malicious / Deception */}
          <path
            d="M 400 130 C 460 130, 480 210, 540 210"
            fill="none"
            stroke={activeOutcome === 'malicious' ? '#5B9CFF' : '#1E2D47'}
            strokeWidth={activeOutcome === 'malicious' ? '3' : '1.5'}
            markerEnd={activeOutcome === 'malicious' ? 'url(#arrow-malicious)' : 'url(#arrow-default)'}
          />

          {/* NODE 1: Incoming Traffic / Internet */}
          <g transform="translate(10, 95)">
            <rect width="110" height="70" rx="8" fill="#0D1422" stroke="#263857" strokeWidth="1.5" />
            <text x="55" y="32" textAnchor="middle" fill="#F4F7FC" fontSize="12" fontWeight="700">Client Traffic</text>
            <text x="55" y="50" textAnchor="middle" fill="#9AAAC0" fontSize="10">HTTP / HTTPS</text>
          </g>

          {/* NODE 2: Cyber Deception Gateway */}
          <g transform="translate(220, 90)">
            <rect
              width="180"
              height="80"
              rx="10"
              fill="#111B2D"
              stroke="var(--accent-primary)"
              strokeWidth="2"
              filter="drop-shadow(0 4px 12px rgba(91, 156, 255, 0.15))"
            />
            <text x="90" y="32" textAnchor="middle" fill="#5B9CFF" fontSize="13" fontWeight="700">Deception Gateway</text>
            <text x="90" y="50" textAnchor="middle" fill="#F4F7FC" fontSize="11" fontWeight="600">Reverse Proxy</text>
            <text x="90" y="66" textAnchor="middle" fill="#9AAAC0" fontSize="9.5">Port 8080 · Policy Router</text>
          </g>

          {/* NODE 2B: AI Detection & Policy Service (Above Gateway) */}
          <g transform="translate(245, 12)">
            <rect width="130" height="42" rx="6" fill="#080D18" stroke="#5CE1D6" strokeWidth="1.2" />
            <text x="65" y="21" textAnchor="middle" fill="#5CE1D6" fontSize="10.5" fontWeight="700">AI Threat Scorer</text>
            <text x="65" y="34" textAnchor="middle" fill="#9AAAC0" fontSize="9">Port 8000 · Model Engine</text>
          </g>

          {/* OUTCOME NODES */}
          {/* Outcome 1: Upstream Origin */}
          <g transform="translate(540, 20)">
            <rect
              width="190"
              height="60"
              rx="8"
              fill={activeOutcome === 'legitimate' ? 'rgba(16, 185, 129, 0.08)' : '#0D1422'}
              stroke={activeOutcome === 'legitimate' ? '#10B981' : '#1C283F'}
              strokeWidth={activeOutcome === 'legitimate' ? '2' : '1.2'}
            />
            <text x="95" y="28" textAnchor="middle" fill={activeOutcome === 'legitimate' ? '#10B981' : '#F4F7FC'} fontSize="11.5" fontWeight="700">
              1. Upstream Origin
            </text>
            <text x="95" y="46" textAnchor="middle" fill="#9AAAC0" fontSize="9.5">
              Protected Application (:5000)
            </text>
          </g>

          {/* Outcome 2: Observation & Monitoring */}
          <g transform="translate(540, 100)">
            <rect
              width="190"
              height="60"
              rx="8"
              fill={activeOutcome === 'suspicious' ? 'rgba(245, 158, 11, 0.08)' : '#0D1422'}
              stroke={activeOutcome === 'suspicious' ? '#F59E0B' : '#1C283F'}
              strokeWidth={activeOutcome === 'suspicious' ? '2' : '1.2'}
            />
            <text x="95" y="28" textAnchor="middle" fill={activeOutcome === 'suspicious' ? '#F59E0B' : '#F4F7FC'} fontSize="11.5" fontWeight="700">
              2. Observation Path
            </text>
            <text x="95" y="46" textAnchor="middle" fill="#9AAAC0" fontSize="9.5">
              Enriched Telemetry / Sticky Monitor
            </text>
          </g>

          {/* Outcome 3: Isolated Deception Runtime */}
          <g transform="translate(540, 180)">
            <rect
              width="190"
              height="60"
              rx="8"
              fill={activeOutcome === 'malicious' ? 'rgba(91, 156, 255, 0.1)' : '#0D1422'}
              stroke={activeOutcome === 'malicious' ? '#5B9CFF' : '#1C283F'}
              strokeWidth={activeOutcome === 'malicious' ? '2' : '1.2'}
            />
            <text x="95" y="28" textAnchor="middle" fill={activeOutcome === 'malicious' ? '#5B9CFF' : '#F4F7FC'} fontSize="11.5" fontWeight="700">
              3. Deception Runtime
            </text>
            <text x="95" y="46" textAnchor="middle" fill="#9AAAC0" fontSize="9.5">
              Synthetic Deception Graph (:5050)
            </text>
          </g>
        </svg>
      </div>

      {/* Dynamic Simulation Outcome Callout */}
      <div
        style={{
          padding: '1.25rem 1.5rem',
          backgroundColor: current.bgColor,
          borderTop: `1px solid ${current.borderColor}`,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '1rem',
          transition: 'all var(--transition-fast)',
        }}
      >
        <div style={{ maxWidth: '480px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem', marginBottom: '0.35rem' }}>
            <span style={{ fontSize: '0.75rem', fontWeight: 800, textTransform: 'uppercase', color: current.color, letterSpacing: '0.06em' }}>
              Outcome: {current.decision}
            </span>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>·</span>
            <span style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>
              Risk: {current.score}
            </span>
          </div>
          <p style={{ fontSize: '0.825rem', color: 'var(--text-main)', lineHeight: 1.5 }}>
            {current.description}
          </p>
        </div>

        <div
          style={{
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'flex-end',
            fontFamily: 'var(--font-mono)',
            fontSize: '0.75rem',
            color: 'var(--text-muted)',
          }}
        >
          <span>Destination Target:</span>
          <span style={{ color: current.color, fontWeight: 600 }}>{current.destination}</span>
        </div>
      </div>
    </div>
  );
}
