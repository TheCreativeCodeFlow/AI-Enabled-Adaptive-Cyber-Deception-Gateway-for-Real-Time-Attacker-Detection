import React from 'react';
import Card from '../components/ui/Card';
import Button from '../components/ui/Button';
import Icon from '../components/ui/Icon';
import Badge from '../components/ui/Badge';
import { auth } from '../services/auth';

/**
 * Cyber Deception Gateway — Authenticated Protected Workspace (Stage 2)
 *
 * Demonstrates successful authentication, token persistence, role verification,
 * and working session termination (Sign Out).
 */
export default function ProtectedWorkspacePlaceholder({
  operator,
  onNavigate,
  onLogout,
  title = 'Organization Workspace',
  subtitle = 'Protected Application Management & Deception Telemetry',
  isAdminView = false,
}) {
  return (
    <div
      style={{
        minHeight: '100vh',
        backgroundColor: 'var(--bg-main)',
        display: 'flex',
        flexDirection: 'column',
      }}
    >
      {/* Top Bar */}
      <header
        style={{
          height: 'var(--nav-height)',
          backgroundColor: 'var(--bg-secondary)',
          borderBottom: '1px solid var(--border-subtle)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '0 2rem',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <div
            style={{
              width: '34px',
              height: '34px',
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
          <span style={{ fontWeight: 700, fontSize: '1rem', color: 'var(--text-main)' }}>
            Cyber Deception Gateway
          </span>
          <span style={{ color: 'var(--text-dim)', margin: '0 0.25rem' }}>/</span>
          <span style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
            {title}
          </span>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '1.25rem' }}>
          {/* Operator Meta */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', textAlign: 'right' }}>
            <div style={{ display: 'flex', flexDirection: 'column' }}>
              <span style={{ fontSize: '0.875rem', fontWeight: 600, color: 'var(--text-main)' }}>
                {operator?.username || 'Operator'}
              </span>
              <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                {operator?.email || 'operator@deception.local'}
              </span>
            </div>
            <Badge
              variant={operator?.role === 'admin' ? 'eyebrow' : 'neutral'}
              style={{ fontSize: '0.7rem', padding: '0.2rem 0.55rem' }}
            >
              {operator?.role || 'analyst'}
            </Badge>
          </div>

          {/* Admin Switcher if role is admin */}
          {operator?.role === 'admin' && (
            <Button
              variant="secondary"
              size="sm"
              onClick={() => onNavigate(isAdminView ? '/app' : '/admin')}
            >
              {isAdminView ? 'Switch to Org Workspace' : 'Platform Admin'}
            </Button>
          )}

          {/* Sign Out Button */}
          <Button
            variant="subtle"
            size="sm"
            onClick={onLogout}
            style={{ color: '#F87171' }}
          >
            Sign Out
          </Button>
        </div>
      </header>

      {/* Main Workspace Body */}
      <main style={{ flexGrow: 1, padding: '3.5rem 1.5rem', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        <div style={{ width: '100%', maxWidth: '780px' }}>
          <Card
            style={{
              padding: '3rem 2.5rem',
              boxShadow: '0 20px 48px rgba(0, 0, 0, 0.4)',
              border: '1px solid var(--border-medium)',
              textAlign: 'center',
            }}
          >
            <div
              style={{
                width: '54px',
                height: '54px',
                margin: '0 auto 1.5rem',
                borderRadius: 'var(--radius-sm)',
                backgroundColor: 'rgba(16, 185, 129, 0.12)',
                border: '1px solid rgba(16, 185, 129, 0.35)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: '#10B981',
              }}
            >
              <Icon name="check" size={26} color="#10B981" />
            </div>

            <div style={{ marginBottom: '1rem' }}>
              <span
                style={{
                  fontSize: '0.75rem',
                  fontFamily: 'var(--font-mono)',
                  color: 'var(--accent-secondary)',
                  backgroundColor: 'var(--accent-secondary-subtle)',
                  padding: '0.3rem 0.75rem',
                  borderRadius: 'var(--radius-full)',
                  border: '1px solid var(--accent-secondary-border)',
                  textTransform: 'uppercase',
                  fontWeight: 700,
                  letterSpacing: '0.06em',
                }}
              >
                Stage 2 Authentication Verified
              </span>
            </div>

            <h2
              style={{
                fontSize: '1.85rem',
                fontWeight: 700,
                color: 'var(--text-main)',
                marginBottom: '0.5rem',
                letterSpacing: '-0.02em',
              }}
            >
              {title}
            </h2>

            <p style={{ fontSize: '0.95rem', color: 'var(--text-secondary)', marginBottom: '2.5rem', maxWidth: '580px', margin: '0 auto 2.5rem' }}>
              {subtitle}. Your session is authenticated and secured with a signed operator JWT.
            </p>

            {/* Session Verification Breakdown */}
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
                gap: '1rem',
                marginBottom: '2.5rem',
                textAlign: 'left',
              }}
            >
              <div style={{ padding: '1rem', backgroundColor: 'var(--bg-main)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-subtle)' }}>
                <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>
                  Operator Username
                </span>
                <p style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--text-main)', marginTop: '0.2rem' }}>
                  {operator?.username}
                </p>
              </div>

              <div style={{ padding: '1rem', backgroundColor: 'var(--bg-main)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-subtle)' }}>
                <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>
                  Assigned RBAC Role
                </span>
                <p style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--accent-primary)', marginTop: '0.2rem' }}>
                  {operator?.role}
                </p>
              </div>

              <div style={{ padding: '1rem', backgroundColor: 'var(--bg-main)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-subtle)' }}>
                <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>
                  JWT Token Status
                </span>
                <p style={{ fontSize: '0.95rem', fontWeight: 700, color: '#10B981', marginTop: '0.2rem' }}>
                  Active (8-hour lease)
                </p>
              </div>
            </div>

            {/* Next Stage Note */}
            <div
              style={{
                padding: '1.25rem',
                backgroundColor: 'rgba(91, 156, 255, 0.05)',
                border: '1px dashed var(--border-medium)',
                borderRadius: 'var(--radius-sm)',
                marginBottom: '2rem',
                fontSize: '0.85rem',
                color: 'var(--text-secondary)',
                lineHeight: 1.6,
                textAlign: 'left',
              }}
            >
              <strong style={{ color: 'var(--text-main)' }}>Staging Roadmap: </strong>
              Stage 2 has successfully established the operator login and registration pipeline with real backend authentication. In subsequent stages, this view will be replaced by the 6-step Application Onboarding Wizard (Stage 3), 10-view Tenant Operations Dashboard (Stage 4), and Platform Administrator Console (Stage 5).
            </div>

            <div style={{ display: 'flex', justifyContent: 'center', gap: '1rem', flexWrap: 'wrap' }}>
              <Button
                variant="secondary"
                onClick={() => onNavigate('/')}
              >
                View Public Landing Page
              </Button>
              <Button
                variant="primary"
                onClick={onLogout}
              >
                Sign Out Session
              </Button>
            </div>
          </Card>
        </div>
      </main>
    </div>
  );
}
