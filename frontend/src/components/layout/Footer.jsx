import React from 'react';
import Icon from '../ui/Icon';

/**
 * Cyber Deception Gateway — Footer
 * Factual enterprise footer with verified navigation and architecture references.
 */
export default function Footer({ onNavigate }) {
  const handleNavClick = (e, sectionId) => {
    e.preventDefault();
    if (window.location.pathname !== '/') {
      onNavigate('/');
      setTimeout(() => {
        const el = document.getElementById(sectionId);
        if (el) el.scrollIntoView({ behavior: 'smooth' });
      }, 100);
      return;
    }
    const el = document.getElementById(sectionId);
    if (el) el.scrollIntoView({ behavior: 'smooth' });
  };

  return (
    <footer
      style={{
        backgroundColor: '#050912',
        borderTop: '1px solid var(--border-subtle)',
        padding: '4.5rem 0 2.5rem',
      }}
    >
      <div className="container">
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
            gap: '3rem',
            marginBottom: '3.5rem',
          }}
        >
          {/* Col 1: Brand & Description */}
          <div style={{ maxWidth: '320px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem', marginBottom: '1rem' }}>
              <div
                style={{
                  width: '32px',
                  height: '32px',
                  borderRadius: 'var(--radius-sm)',
                  backgroundColor: 'var(--accent-primary-subtle)',
                  border: '1px solid var(--accent-primary-border)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  color: 'var(--accent-primary)',
                }}
              >
                <Icon name="shield" size={18} color="var(--accent-primary)" />
              </div>
              <span style={{ fontWeight: 700, fontSize: '1rem', color: 'var(--text-main)', letterSpacing: '-0.01em' }}>
                Cyber Deception Gateway
              </span>
            </div>
            <p style={{ fontSize: '0.875rem', color: 'var(--text-muted)', lineHeight: 1.6, marginBottom: '1.25rem' }}>
              Adaptive application security gateway combining real-time HTTP traffic analysis, AI-enabled threat scoring, and policy-governed deception routing.
            </p>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.75rem', color: 'var(--text-dim)' }}>
              <span>Research & Verification Platform</span>
            </div>
          </div>

          {/* Col 2: Product */}
          <div>
            <h4 style={{ fontSize: '0.85rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--text-main)', marginBottom: '1.25rem' }}>
              Product
            </h4>
            <ul style={{ listStyle: 'none', display: 'flex', flexDirection: 'column', gap: '0.75rem', fontSize: '0.875rem' }}>
              <li>
                <a href="#capabilities" onClick={(e) => handleNavClick(e, 'capabilities')} style={{ color: 'var(--text-secondary)' }} className="footer-link">
                  Core Capabilities
                </a>
              </li>
              <li>
                <a href="#how-it-works" onClick={(e) => handleNavClick(e, 'how-it-works')} style={{ color: 'var(--text-secondary)' }} className="footer-link">
                  How It Works
                </a>
              </li>
              <li>
                <a href="#architecture" onClick={(e) => handleNavClick(e, 'architecture')} style={{ color: 'var(--text-secondary)' }} className="footer-link">
                  System Architecture
                </a>
              </li>
              <li>
                <a href="#security" onClick={(e) => handleNavClick(e, 'security')} style={{ color: 'var(--text-secondary)' }} className="footer-link">
                  Security Principles
                </a>
              </li>
            </ul>
          </div>

          {/* Col 3: Architecture & Gateway */}
          <div>
            <h4 style={{ fontSize: '0.85rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--text-main)', marginBottom: '1.25rem' }}>
              Architecture
            </h4>
            <ul style={{ listStyle: 'none', display: 'flex', flexDirection: 'column', gap: '0.75rem', fontSize: '0.875rem' }}>
              <li>
                <a href="#architecture" onClick={(e) => handleNavClick(e, 'architecture')} style={{ color: 'var(--text-secondary)' }} className="footer-link">
                  Reverse-Proxy Gateway
                </a>
              </li>
              <li>
                <a href="#architecture" onClick={(e) => handleNavClick(e, 'architecture')} style={{ color: 'var(--text-secondary)' }} className="footer-link">
                  AI Detection Service
                </a>
              </li>
              <li>
                <a href="#architecture" onClick={(e) => handleNavClick(e, 'architecture')} style={{ color: 'var(--text-secondary)' }} className="footer-link">
                  Deception State Graph (DSG)
                </a>
              </li>
              <li>
                <a href="#architecture" onClick={(e) => handleNavClick(e, 'architecture')} style={{ color: 'var(--text-secondary)' }} className="footer-link">
                  Policy Evaluation Engine
                </a>
              </li>
            </ul>
          </div>

          {/* Col 4: Platform Access */}
          <div>
            <h4 style={{ fontSize: '0.85rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--text-main)', marginBottom: '1.25rem' }}>
              Platform
            </h4>
            <ul style={{ listStyle: 'none', display: 'flex', flexDirection: 'column', gap: '0.75rem', fontSize: '0.875rem' }}>
              <li>
                <a
                  href="/login"
                  onClick={(e) => {
                    e.preventDefault();
                    onNavigate('/login');
                  }}
                  style={{ color: 'var(--text-secondary)' }}
                  className="footer-link"
                >
                  Operator Sign In
                </a>
              </li>
              <li>
                <a
                  href="/register"
                  onClick={(e) => {
                    e.preventDefault();
                    onNavigate('/register');
                  }}
                  style={{ color: 'var(--text-secondary)' }}
                  className="footer-link"
                >
                  Create Workspace
                </a>
              </li>
              <li>
                <a
                  href="#architecture"
                  onClick={(e) => handleNavClick(e, 'architecture')}
                  style={{ color: 'var(--text-secondary)' }}
                  className="footer-link"
                >
                  Technical Documentation
                </a>
              </li>
            </ul>
          </div>
        </div>

        {/* Factual Disclaimer & Notice */}
        <div
          style={{
            padding: '1.25rem 1.5rem',
            backgroundColor: 'rgba(13, 20, 34, 0.6)',
            borderRadius: 'var(--radius-sm)',
            border: '1px solid var(--border-subtle)',
            marginBottom: '2rem',
            fontSize: '0.8rem',
            color: 'var(--text-muted)',
            lineHeight: 1.6,
          }}
        >
          <strong style={{ color: 'var(--text-secondary)' }}>Defensive Scope & Governance: </strong>
          Cyber Deception Gateway operates at the HTTP/HTTPS application layer. It evaluates incoming requests against policy-controlled detection criteria and directs traffic between upstream origins and isolated deception runtime environments. Onboarding, domain ownership verification, origin configuration, and routing activation are required before traffic can be routed through the gateway.
        </div>

        {/* Bottom Bar */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            paddingTop: '1.5rem',
            borderTop: '1px solid var(--border-subtle)',
            fontSize: '0.8rem',
            color: 'var(--text-dim)',
            flexWrap: 'wrap',
            gap: '1rem',
          }}
        >
          <div>
            © {new Date().getFullYear()} Cyber Deception Gateway. All rights reserved.
          </div>
          <div style={{ display: 'flex', gap: '1.5rem' }}>
            <span>Policy-Governed Routing</span>
            <span>Adaptive Threat Isolation</span>
          </div>
        </div>
      </div>

      <style>{`
        .footer-link:hover {
          color: var(--accent-primary) !important;
        }
      `}</style>
    </footer>
  );
}
