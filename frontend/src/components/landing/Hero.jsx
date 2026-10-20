import React from 'react';
import Button from '../ui/Button';
import Badge from '../ui/Badge';
import Icon from '../ui/Icon';
import GatewayDiagram from './GatewayDiagram';

/**
 * Cyber Deception Gateway — Hero Section
 * Two-column layout with value proposition and interactive architecture visualization.
 */
export default function Hero({ onNavigate }) {
  const handleScrollToSection = (sectionId) => {
    const el = document.getElementById(sectionId);
    if (el) {
      el.scrollIntoView({ behavior: 'smooth' });
    }
  };

  return (
    <section
      style={{
        padding: '5.5rem 0 4.5rem',
        position: 'relative',
        overflow: 'hidden',
        background: 'radial-gradient(ellipse at 50% 0%, rgba(91, 156, 255, 0.08) 0%, transparent 70%)',
        borderBottom: '1px solid var(--border-subtle)',
      }}
    >
      <div className="container">
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))',
            gap: '3.5rem',
            alignItems: 'center',
          }}
          className="hero-grid"
        >
          {/* Left Column: Headlines & Call to Action */}
          <div style={{ maxWidth: '580px' }}>
            <div style={{ marginBottom: '1.25rem' }}>
              <Badge variant="eyebrow" icon={<Icon name="shield" size={14} color="var(--accent-primary)" />}>
                AI-Powered Application Security
              </Badge>
            </div>

            <h1
              style={{
                fontSize: 'clamp(2.4rem, 4.5vw, 3.4rem)',
                fontWeight: 800,
                lineHeight: 1.15,
                letterSpacing: '-0.03em',
                color: 'var(--text-main)',
                marginBottom: '1.5rem',
              }}
            >
              Detect the threat.
              <br />
              Control the path.
              <br />
              <span style={{ color: 'var(--accent-primary)' }}>Deceive with intelligence.</span>
            </h1>

            <p
              style={{
                fontSize: '1.125rem',
                color: 'var(--text-secondary)',
                lineHeight: 1.65,
                marginBottom: '2rem',
              }}
            >
              An adaptive cyber deception gateway that analyzes application traffic, identifies suspicious behavior, and applies policy-controlled routing to help protect legitimate application resources.
            </p>

            {/* CTAs */}
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '1rem',
                flexWrap: 'wrap',
                marginBottom: '1.75rem',
              }}
            >
              <Button
                variant="primary"
                size="lg"
                icon={<Icon name="arrow-right" size={18} color="#050A14" />}
                iconPosition="right"
                onClick={() => onNavigate('/register')}
              >
                Get Started
              </Button>
              <Button
                variant="secondary"
                size="lg"
                onClick={() => handleScrollToSection('architecture')}
              >
                Explore the Platform
              </Button>
            </div>

            {/* Trust & Boundary Line */}
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.65rem',
                fontSize: '0.825rem',
                color: 'var(--text-muted)',
                lineHeight: 1.5,
              }}
            >
              <Icon name="check" size={16} color="var(--accent-secondary)" />
              <span>
                Focused on application-layer traffic analysis, policy-governed routing, and adaptive deception environments.
              </span>
            </div>
          </div>

          {/* Right Column: Gateway Architecture Visual */}
          <div>
            <GatewayDiagram />
          </div>
        </div>
      </div>

      <style>{`
        @media (max-width: 900px) {
          .hero-grid {
            grid-template-columns: 1fr !important;
            gap: 2.5rem !important;
          }
        }
      `}</style>
    </section>
  );
}
