import React from 'react';
import Card from '../ui/Card';
import Icon from '../ui/Icon';

/**
 * Cyber Deception Gateway — Security-Focused Design Principles Section
 *
 * Three concise, factual sections:
 * 1. Controlled Routing Decisions
 * 2. Isolated Deception Environments
 * 3. Observable Security Events
 */
export default function SecurityPrinciples() {
  const principles = [
    {
      title: 'Controlled Routing Decisions',
      icon: 'route',
      description:
        'Traffic routing is governed by explicit operator thresholds, sensitivity configurations, and session stickiness policies. The gateway prioritizes deterministic fail-safe handling: if an anomaly detection engine experiences an unhandled failure or timeout, the configurable fallback policy dictates whether requests pass through or route to quarantine.',
      points: [
        'Deterministic sensitivity threshold (default score 0.70)',
        'Configurable failure policies (quarantine vs bypass)',
        'Persistent session stickiness to prevent attacker re-entry',
      ],
    },
    {
      title: 'Isolated Deception Environments',
      icon: 'lock',
      description:
        'The deception runtime operates within dedicated Docker bridge networks with no direct filesystem or credential access to the protected origin. Attackers engage with a synthetic Deception State Graph (DSG) that returns plausible responses while collecting attacker behavioral artifacts.',
      points: [
        'Dedicated network segmentation between deception and origin',
        'Synthetic response generation with zero host file exposure',
        'Strict payload size limits and LRU session eviction',
      ],
    },
    {
      title: 'Observable Security Events',
      icon: 'activity',
      description:
        'Every routing determination generates an immutable security event log containing request metadata, inference latency, threat scoring, and destination targets. Client IP addresses and sensitive query parameters are appropriately sanitized for operator inspection.',
      points: [
        'Granular request-level telemetry and classification scores',
        'Deception Effectiveness Score (DES) calculation',
        'Operator audit logs tracking route state and verification events',
      ],
    },
  ];

  return (
    <section id="security" className="section">
      <div className="container">
        <div className="section-header">
          <span className="section-eyebrow">Engineering Integrity</span>
          <h2 className="section-title">Security-Focused Design Principles</h2>
          <p className="section-description">
            A principled engineering approach focused on predictable system behavior, verifiable isolation boundaries, and transparent operational observability.
          </p>
        </div>

        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))',
            gap: '2rem',
          }}
        >
          {principles.map((p) => (
            <Card
              key={p.title}
              style={{
                display: 'flex',
                flexDirection: 'column',
                justifyContent: 'space-between',
              }}
            >
              <div>
                <div
                  style={{
                    width: '44px',
                    height: '44px',
                    borderRadius: 'var(--radius-sm)',
                    backgroundColor: 'var(--accent-primary-subtle)',
                    border: '1px solid var(--accent-primary-border)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    color: 'var(--accent-primary)',
                    marginBottom: '1.25rem',
                  }}
                >
                  <Icon name={p.icon} size={22} color="var(--accent-primary)" />
                </div>

                <h3
                  style={{
                    fontSize: '1.25rem',
                    fontWeight: 700,
                    color: 'var(--text-main)',
                    marginBottom: '0.75rem',
                    letterSpacing: '-0.01em',
                  }}
                >
                  {p.title}
                </h3>

                <p
                  style={{
                    fontSize: '0.92rem',
                    color: 'var(--text-secondary)',
                    lineHeight: 1.6,
                    marginBottom: '1.5rem',
                  }}
                >
                  {p.description}
                </p>
              </div>

              <div
                style={{
                  paddingTop: '1.25rem',
                  borderTop: '1px solid var(--border-subtle)',
                }}
              >
                <ul
                  style={{
                    listStyle: 'none',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '0.65rem',
                  }}
                >
                  {p.points.map((pt) => (
                    <li
                      key={pt}
                      style={{
                        display: 'flex',
                        alignItems: 'flex-start',
                        gap: '0.5rem',
                        fontSize: '0.825rem',
                        color: 'var(--text-main)',
                        lineHeight: 1.4,
                      }}
                    >
                      <span style={{ color: 'var(--accent-secondary)', marginTop: '0.1rem' }}>
                        <Icon name="check" size={14} color="var(--accent-secondary)" />
                      </span>
                      <span>{pt}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </Card>
          ))}
        </div>
      </div>
    </section>
  );
}
