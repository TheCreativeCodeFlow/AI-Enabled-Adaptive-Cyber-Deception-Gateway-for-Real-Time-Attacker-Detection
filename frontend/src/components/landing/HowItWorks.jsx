import React from 'react';
import Card from '../ui/Card';
import Icon from '../ui/Icon';

/**
 * Cyber Deception Gateway — How It Works Section
 * Responsive 4-step process with connectors and verified operational prerequisites.
 */
export default function HowItWorks() {
  const steps = [
    {
      num: '01',
      title: 'Connect an Application',
      description: 'Register the target application with domain ownership verification (DNS TXT challenge) and validate the upstream origin address against SSRF vulnerabilities.',
      note: 'Requires domain ownership proof before activation.',
    },
    {
      num: '02',
      title: 'Analyze Incoming Traffic',
      description: 'The reverse-proxy gateway intercepts incoming HTTP/HTTPS requests and extracts structured payload features, query parameters, and session tokens.',
      note: 'Sub-millisecond inspection overhead.',
    },
    {
      num: '03',
      title: 'Evaluate Risk & Policy',
      description: 'The AI detection service scores request anomalies in real-time. Policy rules evaluate the confidence score against configured thresholds (default 0.70).',
      note: 'Configurable sensitivity and fail-safe fallback.',
    },
    {
      num: '04',
      title: 'Route to Environment',
      description: 'Traffic dispatches dynamically: legitimate requests forward to the origin server; confirmed malicious requests divert to the isolated deception runtime.',
      note: 'Preserves origin confidentiality and uptime.',
    },
  ];

  return (
    <section id="how-it-works" className="section">
      <div className="container">
        <div className="section-header">
          <span className="section-eyebrow">Operational Workflow</span>
          <h2 className="section-title">How the Gateway Operates</h2>
          <p className="section-description">
            A structured four-step pipeline that transitions application traffic from initial domain onboarding to policy-controlled, real-time routing.
          </p>
        </div>

        {/* 4-Step Grid with Connectors */}
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))',
            gap: '1.75rem',
            position: 'relative',
            marginBottom: '3rem',
          }}
          className="steps-grid"
        >
          {steps.map((step) => (
            <Card
              key={step.num}
              style={{
                position: 'relative',
                display: 'flex',
                flexDirection: 'column',
                justifyContent: 'space-between',
              }}
            >
              <div>
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'baseline',
                    justifyContent: 'space-between',
                    marginBottom: '1rem',
                  }}
                >
                  <span
                    style={{
                      fontFamily: 'var(--font-mono)',
                      fontSize: '1.75rem',
                      fontWeight: 800,
                      color: 'var(--accent-primary)',
                      lineHeight: 1,
                    }}
                  >
                    {step.num}
                  </span>
                  <span
                    style={{
                      fontSize: '0.7rem',
                      fontFamily: 'var(--font-mono)',
                      textTransform: 'uppercase',
                      color: 'var(--text-muted)',
                      letterSpacing: '0.05em',
                    }}
                  >
                    Phase {step.num}
                  </span>
                </div>

                <h3
                  style={{
                    fontSize: '1.15rem',
                    fontWeight: 700,
                    color: 'var(--text-main)',
                    marginBottom: '0.75rem',
                  }}
                >
                  {step.title}
                </h3>

                <p
                  style={{
                    fontSize: '0.9rem',
                    color: 'var(--text-secondary)',
                    lineHeight: 1.55,
                    marginBottom: '1.5rem',
                  }}
                >
                  {step.description}
                </p>
              </div>

              <div
                style={{
                  paddingTop: '0.85rem',
                  borderTop: '1px solid rgba(28, 40, 63, 0.6)',
                  fontSize: '0.78rem',
                  color: 'var(--text-muted)',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.4rem',
                }}
              >
                <Icon name="check" size={14} color="var(--accent-secondary)" />
                <span>{step.note}</span>
              </div>
            </Card>
          ))}
        </div>

        {/* Operational Boundary Notice */}
        <div
          style={{
            backgroundColor: 'var(--bg-card)',
            border: '1px solid var(--border-subtle)',
            borderRadius: 'var(--radius-md)',
            padding: '1.5rem 1.75rem',
            display: 'flex',
            alignItems: 'flex-start',
            gap: '1rem',
          }}
        >
          <div
            style={{
              padding: '0.4rem',
              borderRadius: 'var(--radius-sm)',
              backgroundColor: 'var(--accent-primary-subtle)',
              color: 'var(--accent-primary)',
              marginTop: '0.1rem',
            }}
          >
            <Icon name="shield" size={18} color="var(--accent-primary)" />
          </div>
          <div>
            <h4 style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--text-main)', marginBottom: '0.35rem' }}>
              Onboarding & Domain Ownership Requirement
            </h4>
            <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
              Application onboarding, domain ownership verification (DNS TXT challenge), SSRF-safe origin configuration, and explicit routing cutover are strictly separate operational steps. Entering a hostname or URL into the platform does not place it behind the gateway until DNS CNAME cutover and verification checks have successfully concluded.
            </p>
          </div>
        </div>
      </div>
    </section>
  );
}
