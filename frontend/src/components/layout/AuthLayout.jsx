import React from 'react';
import Icon from '../ui/Icon';

/**
 * Cyber Deception Gateway — Authentication Two-Column Layout (Stage 2)
 *
 * Left panel: Brand identity, core defensive benefits, and technical illustration.
 * Right panel: Centered authentication card container.
 */
export default function AuthLayout({ children, onNavigate }) {
  const benefits = [
    {
      icon: 'radar',
      title: 'Real-Time Anomaly Scoring',
      desc: 'Machine learning inference scores request anomalies at the perimeter without latency overhead.',
    },
    {
      icon: 'route',
      title: 'Policy-Governed Routing',
      desc: 'Dynamic traffic redirection based on configurable threat thresholds and session context.',
    },
    {
      icon: 'layers',
      title: 'Isolated Deception Runtime',
      desc: 'Synthetic Deception State Graph traps malicious actors while shielding upstream origin servers.',
    },
    {
      icon: 'activity',
      title: 'Granular Attacker Forensics',
      desc: 'Immutable security event logging and attribution without compromising production data.',
    },
  ];

  return (
    <div className="auth-page-container">
      {/* Left Panel: Brand & Benefits */}
      <aside className="auth-panel-left">
        {/* Brand Header */}
        <div>
          <a
            href="/"
            onClick={(e) => {
              e.preventDefault();
              onNavigate('/');
            }}
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '0.75rem',
              color: 'var(--text-main)',
              marginBottom: '3rem',
            }}
            aria-label="Return to Cyber Deception Gateway Home"
          >
            <div
              style={{
                width: '38px',
                height: '38px',
                borderRadius: 'var(--radius-sm)',
                backgroundColor: 'var(--accent-primary-subtle)',
                border: '1px solid var(--accent-primary-border)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: 'var(--accent-primary)',
              }}
            >
              <Icon name="shield" size={22} color="var(--accent-primary)" />
            </div>
            <div style={{ display: 'flex', flexDirection: 'column' }}>
              <span style={{ fontWeight: 700, fontSize: '1.05rem', letterSpacing: '-0.02em', lineHeight: 1.2 }}>
                Cyber Deception Gateway
              </span>
              <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', fontWeight: 500, letterSpacing: '0.04em', textTransform: 'uppercase' }}>
                Adaptive Defense Platform
              </span>
            </div>
          </a>

          <h1
            style={{
              fontSize: '2.4rem',
              fontWeight: 800,
              letterSpacing: '-0.025em',
              color: 'var(--text-main)',
              lineHeight: 1.2,
              marginBottom: '1rem',
            }}
          >
            Secure your <br />
            <span style={{ color: 'var(--accent-primary)' }}>applications.</span>
          </h1>

          <p
            style={{
              fontSize: '1rem',
              color: 'var(--text-secondary)',
              lineHeight: 1.6,
              maxWidth: '460px',
              marginBottom: '2.5rem',
            }}
          >
            An adaptive cyber deception gateway that analyzes application traffic, identifies suspicious behavior, and applies policy-controlled routing to help protect legitimate application resources.
          </p>

          {/* Benefits List */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem', maxWidth: '480px' }}>
            {benefits.map((b) => (
              <div key={b.title} style={{ display: 'flex', alignItems: 'flex-start', gap: '0.9rem' }}>
                <div
                  style={{
                    width: '32px',
                    height: '32px',
                    borderRadius: 'var(--radius-sm)',
                    backgroundColor: 'rgba(255, 255, 255, 0.04)',
                    border: '1px solid var(--border-subtle)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    color: 'var(--accent-secondary)',
                    flexShrink: 0,
                    marginTop: '0.1rem',
                  }}
                >
                  <Icon name={b.icon} size={16} color="var(--accent-secondary)" />
                </div>
                <div>
                  <h2 style={{ fontSize: '0.925rem', fontWeight: 700, color: 'var(--text-main)', marginBottom: '0.2rem' }}>
                    {b.title}
                  </h2>
                  <p style={{ fontSize: '0.825rem', color: 'var(--text-muted)', lineHeight: 1.5 }}>
                    {b.desc}
                  </p>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Factual Scope Footer Note */}
        <div
          style={{
            paddingTop: '2rem',
            borderTop: '1px solid var(--border-subtle)',
            fontSize: '0.78rem',
            color: 'var(--text-dim)',
            lineHeight: 1.5,
          }}
        >
          <span>Operates at the HTTP/HTTPS application layer with strict domain ownership verification.</span>
        </div>
      </aside>

      {/* Right Panel: Content Card Container */}
      <main className="auth-panel-right">
        <div className="auth-card-container">
          {children}
        </div>
      </main>
    </div>
  );
}
