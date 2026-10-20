import React from 'react';
import Icon from '../components/ui/Icon';
import Button from '../components/ui/Button';

/**
 * Cyber Deception Gateway — Stage 1 Route Placeholder
 *
 * Dedicated placeholder for authentication and dashboard routes.
 * Confirms route intent while maintaining strict Stage 1 boundaries.
 */
export default function RoutePlaceholder({ routeName, routePath, onNavigate }) {
  return (
    <div
      style={{
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '2rem 1.5rem',
        backgroundColor: 'var(--bg-main)',
      }}
    >
      <div
        style={{
          width: '100%',
          maxWidth: '520px',
          backgroundColor: 'var(--bg-card)',
          border: '1px solid var(--border-medium)',
          borderRadius: 'var(--radius-lg)',
          padding: '3rem 2.5rem',
          textAlign: 'center',
          boxShadow: '0 20px 48px rgba(0, 0, 0, 0.4)',
        }}
      >
        <div
          style={{
            width: '56px',
            height: '56px',
            margin: '0 auto 1.5rem',
            borderRadius: 'var(--radius-sm)',
            backgroundColor: 'var(--accent-primary-subtle)',
            border: '1px solid var(--accent-primary-border)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: 'var(--accent-primary)',
          }}
        >
          <Icon name="lock" size={26} color="var(--accent-primary)" />
        </div>

        <span
          style={{
            fontSize: '0.72rem',
            fontFamily: 'var(--font-mono)',
            textTransform: 'uppercase',
            letterSpacing: '0.08em',
            color: 'var(--accent-secondary)',
            backgroundColor: 'var(--accent-secondary-subtle)',
            padding: '0.25rem 0.65rem',
            borderRadius: 'var(--radius-full)',
            border: '1px solid var(--accent-secondary-border)',
            display: 'inline-block',
            marginBottom: '1rem',
          }}
        >
          Stage 1 Implementation Scope
        </span>

        <h2
          style={{
            fontSize: '1.6rem',
            fontWeight: 700,
            color: 'var(--text-main)',
            marginBottom: '0.75rem',
            letterSpacing: '-0.02em',
          }}
        >
          {routeName} Placeholder
        </h2>

        <p
          style={{
            fontSize: '0.925rem',
            color: 'var(--text-secondary)',
            lineHeight: 1.6,
            marginBottom: '1.75rem',
          }}
        >
          The route <code style={{ fontFamily: 'var(--font-mono)', color: 'var(--accent-primary)' }}>{routePath}</code> is confirmed and staged. In accordance with the Stage 1 specification, only the public landing page is active. Authentication, workspace onboarding, and operational dashboards will be connected in subsequent stages.
        </p>

        <div style={{ display: 'flex', justifyContent: 'center' }}>
          <Button
            variant="primary"
            onClick={() => onNavigate('/')}
            icon={<Icon name="arrow-right" size={16} color="#050A14" />}
            iconPosition="right"
          >
            Return to Landing Page
          </Button>
        </div>
      </div>
    </div>
  );
}
