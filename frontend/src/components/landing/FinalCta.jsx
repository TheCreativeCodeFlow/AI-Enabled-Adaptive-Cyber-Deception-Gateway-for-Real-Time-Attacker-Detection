import React from 'react';
import Button from '../ui/Button';
import Icon from '../ui/Icon';

/**
 * Cyber Deception Gateway — Final Call to Action Section
 * Clean, restrained CTA guiding visitors into the platform.
 */
export default function FinalCta({ onNavigate }) {
  const handleScrollToSection = (sectionId) => {
    const el = document.getElementById(sectionId);
    if (el) {
      el.scrollIntoView({ behavior: 'smooth' });
    }
  };

  return (
    <section
      style={{
        padding: '6rem 0',
        backgroundColor: 'var(--bg-secondary)',
        borderTop: '1px solid var(--border-subtle)',
        position: 'relative',
        overflow: 'hidden',
      }}
    >
      <div className="container" style={{ position: 'relative', zIndex: 1 }}>
        <div
          style={{
            maxWidth: '800px',
            margin: '0 auto',
            textAlign: 'center',
            backgroundColor: 'var(--bg-card)',
            border: '1px solid var(--border-medium)',
            borderRadius: 'var(--radius-lg)',
            padding: '4rem 2.5rem',
            boxShadow: '0 24px 64px rgba(0, 0, 0, 0.45)',
          }}
        >
          <div
            style={{
              width: '48px',
              height: '48px',
              borderRadius: 'var(--radius-sm)',
              backgroundColor: 'var(--accent-primary-subtle)',
              border: '1px solid var(--accent-primary-border)',
              display: 'inline-flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: 'var(--accent-primary)',
              marginBottom: '1.5rem',
            }}
          >
            <Icon name="route" size={24} color="var(--accent-primary)" />
          </div>

          <h2
            style={{
              fontSize: 'clamp(2rem, 3.5vw, 2.75rem)',
              fontWeight: 800,
              letterSpacing: '-0.025em',
              color: 'var(--text-main)',
              marginBottom: '1.25rem',
              lineHeight: 1.2,
            }}
          >
            Give suspicious traffic a different path.
          </h2>

          <p
            style={{
              fontSize: '1.1rem',
              color: 'var(--text-secondary)',
              lineHeight: 1.6,
              maxWidth: '620px',
              margin: '0 auto 2.5rem',
            }}
          >
            Explore an adaptive approach to application traffic analysis, policy-controlled routing, and cyber deception.
          </p>

          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '1rem',
              flexWrap: 'wrap',
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
        </div>
      </div>
    </section>
  );
}
